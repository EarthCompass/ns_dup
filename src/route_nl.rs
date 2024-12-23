use std::os::fd::OwnedFd;

use nix::sys::socket;

// To be implemented
// Add route to the routing table
pub struct RouteNl{
	pub nl_fd: OwnedFd,
}

impl RouteNl {
	pub fn new() -> RouteNl{
		let nl_fd = socket::socket(socket::AddressFamily::Netlink, socket::SockType::Raw, socket::SockFlag::empty(), socket::SockProtocol::NetlinkRoute).unwrap();
		RouteNl{
			nl_fd: nl_fd,
		}
	}
	pub fn add_route() -> Result<(), nix::Error>{
		Ok(())
	}
}