const VIRTIO_NET_F_MAC: u32 = 5;

const VIRTIO_STATUS_FAILED: u8 = 128;

const VRING_DESC_F_NEXT: u16 = 1;
const VRING_DESC_F_WRITE: u16 = 2;

const QUEUE_SIZE: u16 = 256;
const MAX_PACKET_SIZE: usize = 2048;
const VIRTIO_NET_HDR_SIZE: usize = 10;
const MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];

#[repr(C, packed)]
struct VringDesc {
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
}

#[repr(C, packed)]
struct VringAvail {
    flags: u16,
    idx: u16,
    ring: [u16; QUEUE_SIZE as usize],
    used_event: u16,
}

#[repr(C, packed)]
struct VringUsedElem {
    id: u32,
    len: u32,
}

#[repr(C, packed)]
struct VringUsed {
    flags: u16,
    idx: u16,
    ring: [VringUsedElem; QUEUE_SIZE as usize],
    avail_event: u16,
}

#[derive(Debug)]
pub struct VirtioNetPci {
    pub selected_queue: u32,
    pub queue_pfns: [u64; 2],
    pub queue_sizes: [u16; 2],
    pub guest_features: u32,
    pub device_features: u32,
    pub status: u8,
    pub isr: u8,
    pub irq_line: u8,
    pub bar0_shadow: u32,

    pub tap_fd: Option<i32>,
    pub guest_mem: *mut u8,
    pub next_rx_idx: u16,

    pub intr_pending: bool,
    /// Buffer for a crafted SYN/ACK response, delivered via try_rx.
    pub     synack_pending: Option<Vec<u8>>,
    arp_reply_pending: Option<Vec<u8>>,
}

impl VirtioNetPci {
    pub fn new(guest_mem: *mut u8, mmio_base: u32) -> Self {
        VirtioNetPci {
            selected_queue: 0,
            queue_pfns: [0; 2],
            queue_sizes: [QUEUE_SIZE; 2],
            guest_features: 0,
            device_features: (1 << VIRTIO_NET_F_MAC),
            status: 0,
            isr: 0,
            irq_line: 11,
            bar0_shadow: mmio_base,
            tap_fd: None,
            guest_mem,
            next_rx_idx: 0,
            intr_pending: false,
            synack_pending: None,
            arp_reply_pending: None,
        }
    }

    pub fn set_tap_fd(&mut self, fd: i32) {
        self.tap_fd = Some(fd);
    }

    pub fn mmio_read(&mut self, offset: u32) -> u32 {
        let val = match offset {
            0x00 => self.device_features,
            0x04 => self.guest_features,
            0x08 => {
                let q = self.selected_queue as usize;
                if q < 2 && self.queue_pfns[q] != 0 {
                    (self.queue_pfns[q] >> 12) as u32
                } else {
                    0
                }
            }
            0x0C => {
                let q = self.selected_queue as usize;
                if q < 2 { self.queue_sizes[q] as u32 } else { 0 }
            }
            0x0E => self.selected_queue,
            0x12 => self.status as u32,
            0x13 => {
                let v = self.isr as u32;
                tracing::info!("mmio_read ISR=0x{:02x}", v);
                self.isr = 0;
                self.intr_pending = false;
                v
            }
            0x14..=0x19 => {
                let i = (offset - 0x14) as usize;
                if i < 6 { MAC[i] as u32 } else { 0 }
            }
            0x1A => 1u32, // VIRTIO_NET_S_LINK_UP
            _ => 0,
        };
        val
    }

    pub fn mmio_write(&mut self, offset: u32, val: u32) {
        match offset {
            0x04 => {
                self.guest_features = val & self.device_features;
            }
            0x08 => {
                let q = self.selected_queue as usize;
                if q < 2 {
                    self.queue_pfns[q] = (val as u64) << 12;
                }
            }
            0x0E => {
                self.selected_queue = val;
            }
            0x10 => {
                let q = val as usize;
                if q < 2 && self.queue_pfns[q] != 0 {
                    self.handle_queue_kick(q);
                }
            }
            0x12 => {
                self.status = val as u8;
                if self.status & VIRTIO_STATUS_FAILED != 0 {
                    tracing::warn!("virtio-net: guest set FAILED status");
                }
                if self.status == 0 {
                    self.reset();
                }
            }
            0x13 => {
                self.isr = 0;
                self.intr_pending = false;
            }
            _ => {}
        }
    }

    fn reset(&mut self) {
        self.selected_queue = 0;
        self.queue_pfns = [0; 2];
        self.guest_features = 0;
        self.status = 0;
        self.isr = 0;
        self.next_rx_idx = 0;
        self.intr_pending = false;
    }

    pub fn mmio_base(&self) -> u32 { self.bar0_shadow & 0xFFFFF000 }

    fn handle_queue_kick(&mut self, q: usize) {
        tracing::info!("virtio-net queue_kick q={}", q);
        if q != 1 { return; } // only handle TX (queue 1); RX is polled via try_rx()

        let pfn = self.queue_pfns[q];
        if pfn == 0 {
            tracing::warn!("virtio-net TX kick but pfn=0 for q={q}");
            return;
        }

        let desc_off = pfn;
        let avail_off = self.avail_offset(pfn);
        let used_off = self.used_offset(pfn);

        unsafe {
            let avail = &*(self.guest_mem.add(avail_off as usize) as *const VringAvail);
            let used = &mut *(self.guest_mem.add(used_off as usize) as *mut VringUsed);

            let avail_idx = avail.idx;
            let used_idx = used.idx;
            let num_avail = avail_idx.wrapping_sub(used_idx);

            if num_avail == 0 {
                return;
            }

            tracing::info!("virtio-net TX: processing {} descriptors", num_avail);

            for i in 0..num_avail {
                let desc_idx = avail.ring[((used_idx + i) % QUEUE_SIZE) as usize] as u16;
                let mut packet_buf = [0u8; MAX_PACKET_SIZE];
                let mut packet_len = 0usize;
                let mut d_i = desc_idx;

                loop {
                    let desc = &*(self.guest_mem.add(desc_off as usize + d_i as usize * 16) as *const VringDesc);
                    if desc.flags & VRING_DESC_F_WRITE == 0 {
                        let src = self.guest_mem.add(desc.addr as usize);
                        let copy_len = (desc.len as usize).min(MAX_PACKET_SIZE - packet_len);
                        std::ptr::copy_nonoverlapping(src, packet_buf.as_mut_ptr().add(packet_len), copy_len);
                        packet_len += copy_len;
                    }
                    if desc.flags & VRING_DESC_F_NEXT == 0 {
                        break;
                    }
                    d_i = desc.next;
                }

                let eth_len = if packet_len > VIRTIO_NET_HDR_SIZE { packet_len - VIRTIO_NET_HDR_SIZE } else { 0 };
                if eth_len > 0 {
                    let eth_pkt = &packet_buf[VIRTIO_NET_HDR_SIZE..VIRTIO_NET_HDR_SIZE + eth_len];
                    tracing::info!("virtio-net TX: {} bytes, ethtype=0x{:04x} tap_fd={:?}",
                        eth_len,
                        if eth_len >= 14 { u16::from_be_bytes([eth_pkt[12], eth_pkt[13]]) } else { 0 },
                        self.tap_fd);
                    if eth_len >= 54 {
                        let ip_hdr_len = ((eth_pkt[14] & 0x0F) as usize) * 4;
                        let tcp_off = 14 + ip_hdr_len;
                        let tcp_flags = eth_pkt[tcp_off + 13];
                        let tcp_src = (eth_pkt[tcp_off] as u16) << 8 | eth_pkt[tcp_off + 1] as u16;
                        let tcp_dst = (eth_pkt[tcp_off + 2] as u16) << 8 | eth_pkt[tcp_off + 3] as u16;
                        tracing::info!("virtio-net TX: TCP src={} dst={} flags=0x{:02x}", tcp_src, tcp_dst, tcp_flags);
                    }
                    let dump_len = eth_len.min(64);
                    tracing::debug!("virtio-net TX hex: {}",
                        (0..dump_len).map(|i| format!("{:02x}", eth_pkt[i])).collect::<String>());

                    // Write to TAP if available.
                    if let Some(tap_fd) = self.tap_fd {
                        let n = libc::write(tap_fd, eth_pkt.as_ptr() as *const libc::c_void, eth_len);
                        if n < 0 {
                            let e = *libc::__errno_location();
                            tracing::warn!("virtio-net TX: tap write failed errno={}", e);
                        } else {
                            tracing::info!("virtio-net TX: wrote {} bytes to tap", n);
                        }
                    }

                    // Craft SYN/ACK for outgoing TCP SYNs only when TAP is unavailable
                    // (synthetic test mode). When a real TAP fd is present, the host network
                    // stack handles the TCP handshake — don't intercept.
                    if self.tap_fd.is_none() && self.synack_pending.is_none() {
                        if let Some(synack) = Self::craft_synack(eth_pkt) {
                            tracing::info!("virtio-net TX: SYN detected, crafted SYN/ACK ({} bytes)", synack.len());
                            self.synack_pending = Some(synack);
                        }
                    }
                    // Userspace ARP handling only when TAP is unavailable (host kernel handles ARP otherwise)
                    if self.tap_fd.is_none() && self.arp_reply_pending.is_none() && eth_len >= 42
                        && eth_pkt[12] == 0x08 && eth_pkt[13] == 0x06
                    {
                        let opcode = u16::from_be_bytes([eth_pkt[20], eth_pkt[21]]);
                        if opcode == 1 {
                            let tpa = &eth_pkt[38..42];
                            if tpa == [10, 0, 2, 1] {
                                let sha = &eth_pkt[22..28];
                                let spa = &eth_pkt[28..32];
                                let gateway_mac = [0xce, 0x37, 0x22, 0x5e, 0xe0, 0xb9];
                                let gateway_ip = [10, 0, 2, 1];

                                let mut reply = vec![0u8; 42];
                                reply[0..6].copy_from_slice(sha);
                                reply[6..12].copy_from_slice(&gateway_mac);
                                reply[12] = 0x08; reply[13] = 0x06;
                                reply[14] = 0x00; reply[15] = 0x01;
                                reply[16] = 0x08; reply[17] = 0x00;
                                reply[18] = 6;
                                reply[19] = 4;
                                reply[20] = 0x00; reply[21] = 0x02;
                                reply[22..28].copy_from_slice(&gateway_mac);
                                reply[28..32].copy_from_slice(&gateway_ip);
                                reply[32..38].copy_from_slice(sha);
                                reply[38..42].copy_from_slice(spa);

                                tracing::info!("virtio-net TX: ARP request for 10.0.2.1, crafting reply");
                                self.arp_reply_pending = Some(reply);
                            }
                        }
                    }
                } else {
                    tracing::warn!("virtio-net TX: packet_len {} <= hdr_size {}, skipping", packet_len, VIRTIO_NET_HDR_SIZE);
                }

                used.ring[((used_idx + i) % QUEUE_SIZE) as usize] = VringUsedElem {
                    id: desc_idx as u32,
                    len: packet_len as u32,
                };
            }
            used.idx = used_idx.wrapping_add(num_avail);
        }
    }

    /// Ones' complement checksum over a slice of bytes (for IP/TCP headers).
    fn checksum(data: &[u8]) -> u16 {
        let mut sum = 0u32;
        let mut i = 0;
        while i + 1 < data.len() {
            sum += (data[i] as u32) << 8 | data[i + 1] as u32;
            i += 2;
        }
        if i < data.len() {
            sum += (data[i] as u32) << 8;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        !(sum as u16)
    }

    /// If `packet` is an IPv4 TCP SYN to an external port, craft a SYN/ACK
    /// response and return it. Returns None for non-matching packets.
    fn craft_synack(packet: &[u8]) -> Option<Vec<u8>> {
        if packet.len() < 54 { return None; } // eth(14) + ip(20) + tcp(20)
        if packet[12] != 0x08 || packet[13] != 0x00 { return None; } // IPv4 only
        let ip_ihl = packet[14] & 0x0F;
        if ip_ihl < 5 { return None; }
        let ip_hdr_len = (ip_ihl as usize) * 4;
        let ip_total = ((packet[16] as u16) << 8 | packet[17] as u16) as usize;
        if packet.len() < ip_total { return None; }
        if packet[14 + 9] != 6 { return None; } // protocol TCP

        let tcp_off = 14 + ip_hdr_len;
        if tcp_off + 20 > packet.len() { return None; }
        let tcp_flags = packet[tcp_off + 13];
        if tcp_flags & 0x02 == 0 || tcp_flags & 0x10 != 0 { return None; } // SYN, not ACK

        let dst_port = (packet[tcp_off + 2] as u16) << 8 | packet[tcp_off + 3] as u16;
        // Only proxy connections to external destinations (not the host itself)
        if dst_port != 80 && dst_port != 443 { return None; }

        // Extract fields
        let eth_dst = &packet[0..6];
        let eth_src = &packet[6..12];
        let ip_src = &packet[26..30];
        let ip_dst = &packet[30..34];
        let tcp_src_port = &packet[tcp_off..tcp_off + 2];
        let tcp_dst_port = &packet[tcp_off + 2..tcp_off + 4];
        let their_seq = (packet[tcp_off + 4] as u32) << 24
                      | (packet[tcp_off + 5] as u32) << 16
                      | (packet[tcp_off + 6] as u32) << 8
                      | packet[tcp_off + 7] as u32;
        let our_seq: u32 = 0x10000000; // fixed ISN

        // Build SYN/ACK
        let mut reply = vec![0u8; 54]; // eth(14) + ip(20) + tcp(20)

        // Ethernet
        reply[0..6].copy_from_slice(eth_src);
        reply[6..12].copy_from_slice(eth_dst);
        reply[12] = 0x08; reply[13] = 0x00;

        // IP header
        reply[14] = 0x45; // version 4, IHL 5
        reply[15] = 0;    // DSCP/ECN
        let ip_len: u16 = 40; // 20 IP + 20 TCP
        reply[16] = (ip_len >> 8) as u8;
        reply[17] = (ip_len & 0xFF) as u8;
        reply[18] = 0; reply[19] = 0; // ID
        reply[20] = 0x40; reply[21] = 0; // DF
        reply[22] = 64;   // TTL
        reply[23] = 6;    // TCP
        reply[24] = 0; reply[25] = 0; // checksum (placeholder)
        reply[26..30].copy_from_slice(ip_dst); // src IP = original dst
        reply[30..34].copy_from_slice(ip_src); // dst IP = original src
        let ip_csum = Self::checksum(&reply[14..34]);
        reply[24] = (ip_csum >> 8) as u8;
        reply[25] = (ip_csum & 0xFF) as u8;

        // TCP header
        reply[tcp_off..tcp_off + 2].copy_from_slice(tcp_dst_port); // src port = original dst
        reply[tcp_off + 2..tcp_off + 4].copy_from_slice(tcp_src_port); // dst port = original src
        // seq = our_seq
        reply[tcp_off + 4] = (our_seq >> 24) as u8;
        reply[tcp_off + 5] = (our_seq >> 16) as u8;
        reply[tcp_off + 6] = (our_seq >> 8) as u8;
        reply[tcp_off + 7] = our_seq as u8;
        // ack_seq = their_seq + 1
        let ack_seq = their_seq.wrapping_add(1);
        reply[tcp_off + 8] = (ack_seq >> 24) as u8;
        reply[tcp_off + 9] = (ack_seq >> 16) as u8;
        reply[tcp_off + 10] = (ack_seq >> 8) as u8;
        reply[tcp_off + 11] = ack_seq as u8;
        reply[tcp_off + 12] = 0x50; // data offset = 5 (20 bytes)
        reply[tcp_off + 13] = 0x12; // SYN + ACK
        reply[tcp_off + 14] = 0xFF; reply[tcp_off + 15] = 0xFF; // window = 65535
        reply[tcp_off + 16] = 0; reply[tcp_off + 17] = 0; // checksum (placeholder)
        reply[tcp_off + 18] = 0; reply[tcp_off + 19] = 0; // urgent

        // TCP checksum (with pseudo-header)
        let mut tcp_buf = Vec::with_capacity(12 + 20);
        tcp_buf.extend_from_slice(&reply[26..30]); // src IP
        tcp_buf.extend_from_slice(&reply[30..34]); // dst IP
        tcp_buf.push(0); // zero
        tcp_buf.push(6); // protocol
        tcp_buf.push(0); tcp_buf.push(20); // TCP length = 20
        tcp_buf.extend_from_slice(&reply[tcp_off..tcp_off + 20]);
        let tcp_csum = Self::checksum(&tcp_buf);
        reply[tcp_off + 16] = (tcp_csum >> 8) as u8;
        reply[tcp_off + 17] = (tcp_csum & 0xFF) as u8;

        Some(reply)
    }

    pub fn try_rx(&mut self) {
        let pfn = self.queue_pfns[0];
        if pfn == 0 { return; }

        let desc_off = pfn;
        let avail_off = self.avail_offset(pfn);
        let used_off = self.used_offset(pfn);

        // Deliver any pending SYN/ACK before reading from TAP.
        if let Some(synack) = self.synack_pending.take() {
            let len = synack.len();
            tracing::info!("try_rx: delivering pending SYN/ACK ({} bytes)", len);
            unsafe {
                let used = &mut *(self.guest_mem.add(used_off as usize) as *mut VringUsed);
                let avail = &*(self.guest_mem.add(avail_off as usize) as *const VringAvail);
                let avail_idx = avail.idx;
                let used_idx = used.idx;
                let avail_count = avail_idx.wrapping_sub(used_idx);

                if avail_count != 0 {
                    let desc_idx = avail.ring[(used_idx % QUEUE_SIZE) as usize];
                    let mut remaining = len;
                    let mut d_i = desc_idx;

                    while remaining > 0 && d_i < QUEUE_SIZE {
                        let desc = &*(self.guest_mem.add(desc_off as usize + d_i as usize * 16) as *const VringDesc);
                        let copy_len = (desc.len as usize).min(remaining);
                        if desc.flags & VRING_DESC_F_WRITE != 0 {
                            let dst = self.guest_mem.add(desc.addr as usize);
                            std::ptr::copy_nonoverlapping(synack.as_ptr().add(len - remaining), dst, copy_len);
                            remaining -= copy_len;
                        }
                        if desc.flags & VRING_DESC_F_NEXT == 0 || remaining == 0 {
                            break;
                        }
                        d_i = desc.next;
                    }

                    used.ring[(used_idx % QUEUE_SIZE) as usize] = VringUsedElem {
                        id: desc_idx as u32,
                        len: (len - remaining) as u32,
                    };
                    used.idx = used_idx.wrapping_add(1);
                    self.isr |= 1;
                }
            }
        }

        // Deliver any pending ARP reply before reading from TAP.
        if let Some(arp_reply) = self.arp_reply_pending.take() {
            let len = arp_reply.len();
            tracing::info!("try_rx: delivering pending ARP reply ({} bytes)", len);
            unsafe {
                let used = &mut *(self.guest_mem.add(used_off as usize) as *mut VringUsed);
                let avail = &*(self.guest_mem.add(avail_off as usize) as *const VringAvail);
                let avail_idx = avail.idx;
                let used_idx = used.idx;
                let avail_count = avail_idx.wrapping_sub(used_idx);

                if avail_count != 0 {
                    let desc_idx = avail.ring[(used_idx % QUEUE_SIZE) as usize];
                    let mut remaining = len;
                    let mut d_i = desc_idx;

                    while remaining > 0 && d_i < QUEUE_SIZE {
                        let desc = &*(self.guest_mem.add(desc_off as usize + d_i as usize * 16) as *const VringDesc);
                        let copy_len = (desc.len as usize).min(remaining);
                        if desc.flags & VRING_DESC_F_WRITE != 0 {
                            let dst = self.guest_mem.add(desc.addr as usize);
                            std::ptr::copy_nonoverlapping(arp_reply.as_ptr().add(len - remaining), dst, copy_len);
                            remaining -= copy_len;
                        }
                        if desc.flags & VRING_DESC_F_NEXT == 0 || remaining == 0 {
                            break;
                        }
                        d_i = desc.next;
                    }

                    used.ring[(used_idx % QUEUE_SIZE) as usize] = VringUsedElem {
                        id: desc_idx as u32,
                        len: (len - remaining) as u32,
                    };
                    used.idx = used_idx.wrapping_add(1);
                    self.isr |= 1;
                }
            }
        }

        let tap_fd = match self.tap_fd {
            Some(fd) => fd,
            None => return,
        };

        // Prepend a zeroed virtio_net_hdr (10 bytes) before the Ethernet frame.
        // The guest driver expects the header at offset 0 of the RX buffer.
        let hdr = [0u8; VIRTIO_NET_HDR_SIZE];
        let mut buf = [0u8; MAX_PACKET_SIZE];
        buf[..VIRTIO_NET_HDR_SIZE].copy_from_slice(&hdr);

        loop {
            let n = unsafe {
                libc::read(tap_fd, buf.as_mut_ptr().add(VIRTIO_NET_HDR_SIZE) as *mut libc::c_void, buf.len() - VIRTIO_NET_HDR_SIZE)
            };
            if n <= 0 {
                break;
            }
            let len = VIRTIO_NET_HDR_SIZE + n as usize;
            let eth_off = VIRTIO_NET_HDR_SIZE;
            let ethtype = if len >= eth_off + 14 { u16::from_be_bytes([buf[eth_off + 12], buf[eth_off + 13]]) } else { 0 };

            // Skip stale IPv6 multicast packets that consume RX descriptors.
            if ethtype == 0x86DD {
                tracing::debug!("try_rx: skipping IPv6 packet ({} bytes)", len);
                continue;
            }

            let tcps = if len >= eth_off + 54 { format!(" tcp_flags=0x{:02x}", buf[eth_off + 47]) } else { String::new() };
            tracing::info!("try_rx: read {} bytes from TAP fd={} hdr={:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{}",
                len, tap_fd,
                buf[eth_off], buf[eth_off + 1], buf[eth_off + 2], buf[eth_off + 3],
                buf[eth_off + 4], buf[eth_off + 5], buf[eth_off + 6], buf[eth_off + 7],
                buf[eth_off + 8], buf[eth_off + 9], buf[eth_off + 10], buf[eth_off + 11],
                buf[eth_off + 12], buf[eth_off + 13], buf[eth_off + 14], buf[eth_off + 15],
                tcps,
            );

            unsafe {
                let used = &mut *(self.guest_mem.add(used_off as usize) as *mut VringUsed);
                let avail = &*(self.guest_mem.add(avail_off as usize) as *const VringAvail);
                let avail_idx = avail.idx;
                let used_idx = used.idx;
                let avail_count = avail_idx.wrapping_sub(used_idx);

                if avail_count == 0 { break; }

                let desc_idx = avail.ring[(used_idx % QUEUE_SIZE) as usize];
                let first_desc = &*(self.guest_mem.add(desc_off as usize + desc_idx as usize * 16) as *const VringDesc);
                let (d_addr, d_len, d_flags, d_next) = (first_desc.addr, first_desc.len, first_desc.flags, first_desc.next);
                tracing::debug!("try_rx: desc[{}] addr=0x{:x} len={} flags=0x{:x} next={}",
                    desc_idx, d_addr, d_len, d_flags, d_next);
                let mut remaining = len;
                let mut d_i = desc_idx;

                while remaining > 0 && d_i < QUEUE_SIZE {
                    let desc = &*(self.guest_mem.add(desc_off as usize + d_i as usize * 16) as *const VringDesc);
                    let copy_len = (desc.len as usize).min(remaining);
                    if desc.flags & VRING_DESC_F_WRITE != 0 {
                        let dst = self.guest_mem.add(desc.addr as usize);
                        std::ptr::copy_nonoverlapping(buf.as_ptr().add(len - remaining), dst, copy_len);
                        remaining -= copy_len;
                    }
                    if desc.flags & VRING_DESC_F_NEXT == 0 || remaining == 0 {
                        break;
                    }
                    d_i = desc.next;
                }

                used.ring[(used_idx % QUEUE_SIZE) as usize] = VringUsedElem {
                    id: desc_idx as u32,
                    len: (len - remaining) as u32,
                };
                used.idx = used_idx.wrapping_add(1);
            }

            self.isr |= 1;
        }
    }

    /// Capture current device state for snapshot persistence.
    /// Excludes runtime-only fields (tap_fd, guest_mem pointer).
    pub fn capture_state(&self) -> crate::snapshot::VirtioNetState {
        crate::snapshot::VirtioNetState {
            selected_queue: self.selected_queue,
            queue_pfns: self.queue_pfns,
            queue_sizes: self.queue_sizes,
            guest_features: self.guest_features,
            device_features: self.device_features,
            status: self.status,
            isr: self.isr,
            irq_line: self.irq_line,
            bar0_shadow: self.bar0_shadow,
            next_rx_idx: self.next_rx_idx,
            intr_pending: self.intr_pending,
        }
    }

    /// Create a new VirtioNetPci from a previously saved state.
    /// `guest_mem` and `tap_fd` are provided fresh (they are not persisted).
    pub fn from_state(state: &crate::snapshot::VirtioNetState, guest_mem: *mut u8, tap_fd: Option<i32>) -> Self {
        Self {
            selected_queue: state.selected_queue,
            queue_pfns: state.queue_pfns,
            queue_sizes: state.queue_sizes,
            guest_features: state.guest_features,
            device_features: state.device_features,
            status: state.status,
            isr: state.isr,
            irq_line: state.irq_line,
            bar0_shadow: state.bar0_shadow,
            tap_fd,
            guest_mem,
            next_rx_idx: state.next_rx_idx,
            intr_pending: state.intr_pending,
            synack_pending: None,
            arp_reply_pending: None,
        }
    }

    fn avail_offset(&self, pfn: u64) -> u64 {
        pfn + (QUEUE_SIZE as u64) * 16
    }

    fn used_offset(&self, pfn: u64) -> u64 {
        // Linux kernel's virtio-pci legacy driver uses VIRTIO_PCI_VRING_ALIGN = 4096
        // in vring_init, which aligns the used ring to the next page boundary.
        let avail_size = 6 + (QUEUE_SIZE as u64) * 2;
        let off = pfn + (QUEUE_SIZE as u64) * 16 + avail_size;
        (off + 4095) & !4095
    }
}
