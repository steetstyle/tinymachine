#[cfg(test)]
mod tests {
    #[test]
    fn check_sizes() {
        println!("sockaddr_in: {}", std::mem::size_of::<libc::sockaddr_in>());
        println!("in_addr: {}", std::mem::size_of::<libc::in_addr>());
        println!("sa_family_t: {}", std::mem::size_of::<libc::sa_family_t>());
    }
}
