use std::net::Ipv6Addr;

use neli::{
    consts::{
        nl::{ *},
        rtnl::{RtAddrFamily, RtScope, RtTable, Rta, Rtm, RtmFFlags, Rtn, Rtprot},
        socket::*,
    },
    err::NlError,
    nl::{NlPayload, Nlmsghdr},
    rtnl::{Rtattr, Rtmsg},
    socket::NlSocketHandle,
    types::RtBuffer,
};
// To be implemented
// Add route to the routing table


pub fn mod_route(dst: Ipv6Addr, index: i32, is_add: bool) -> Result<(), NlError> {
	let mut socket = NlSocketHandle::connect(NlFamily::Route, Some(nix::unistd::getpid().as_raw() as u32), &[])?;
	socket.block()?;
	let mut route_rtbuff = RtBuffer::new();

	route_rtbuff.push(Rtattr::new(None, Rta::Dst, dst.octets().to_vec())?);
	route_rtbuff.push(Rtattr::new(None, Rta::Priority, 1023)?);
	route_rtbuff.push(Rtattr::new(None, Rta::Oif, index)?);

	let rtmsg = Rtmsg {
		rtm_family: RtAddrFamily::Inet6,
		rtm_dst_len: 128,
		rtm_src_len: 0,
		rtm_tos: 0,
		rtm_table: RtTable::Main,
		rtm_protocol: if is_add {
			Rtprot::Static
		} else {
			Rtprot::Unspec
		},
		rtm_scope: if is_add {
			RtScope::Link
		} else {
			RtScope::Nowhere
		},
		rtm_type: if is_add { Rtn::Unicast } else { Rtn::Unspec },
		rtm_flags: RtmFFlags::empty(),
		rtattrs: route_rtbuff,
	};
	let nlmsg = Nlmsghdr::new(
		None,
		if is_add { Rtm::Newroute } else { Rtm::Delroute },
		NlmFFlags::new(&[
			NlmF::Request,
			NlmF::Ack,
			if is_add { NlmF::Create } else { NlmF::Replace },
		]),
		None,
		None,
		NlPayload::Payload(rtmsg),
	);
	socket.send(nlmsg)?;
	// Wait for the ack
	socket.recv()?;
	Ok(())
}

