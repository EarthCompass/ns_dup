use std::net::SocketAddrV6;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::process::Command;
use nix::{errno::Errno, libc, libc::*, sys::socket};
use nix::sys::socket::{LinkAddr, MsgFlags, SockaddrIn6};
use pnet::packet::{icmpv6, Packet};
use pnet::packet::icmpv6::ndp::NdpOption;
use std::ffi::OsString;
use std::env;
mod route_nl;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        println!("Usage: {} <WAN_IFACE> <LAN_IFACE>", args[0]);
        return;
    }
    let wan_name = &args[1];
    let lan_name = &args[2];

    let mut val = 2;
    let socket_fd = unsafe {
        let raw_socket = libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            (libc::ETH_P_ALL as u16).to_be() as i32,
        );
        match raw_socket {
            -1 => Err(Errno::last()),
            fd => {
                // Safe because libc::socket returned success
                Ok(OwnedFd::from_raw_fd(fd))
            }
        }
    }.expect("Failed to create socket");

    let mut bpf = unsafe {
        [   
            BPF_STMT((BPF_LD | BPF_H | BPF_ABS) as u16, 12),
            BPF_JUMP((BPF_JMP | BPF_JEQ | BPF_K) as u16, 0x86dd as u32, 0, 5),
            BPF_STMT((BPF_LD | BPF_B | BPF_ABS) as u16, 14+6),
            BPF_JUMP((BPF_JMP | BPF_JEQ | BPF_K) as u16, IPPROTO_ICMPV6 as u32, 0, 3),
            BPF_STMT((BPF_LD | BPF_B | BPF_ABS) as u16, 14+40),
            BPF_JUMP((BPF_JMP | BPF_JEQ | BPF_K) as u16, 135, 0, 1),
            BPF_STMT((BPF_RET | BPF_K) as u16, 0xffffffff),
            BPF_STMT((BPF_RET | BPF_K) as u16, 0),
        ]
    };
    let bpf_prog = sock_fprog {
        len: bpf.len() as u16,
        filter: bpf.as_mut_ptr(),
    };
    let res = unsafe {
        let res = libc::setsockopt(
            socket_fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_ATTACH_FILTER,
            &bpf_prog as *const _ as *const libc::c_void,
            std::mem::size_of_val(&bpf_prog) as u32,
        );
        Errno::result(res).map(drop)
    };
    res.expect("Failed to set filter");
    let ping_fd = unsafe {
        let raw_socket = libc::socket(
            libc::AF_INET6,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::IPPROTO_ICMPV6,
        );
        match raw_socket {
            -1 => Err(Errno::last()),
            fd => {
                // Safe because libc::socket returned success
                Ok(OwnedFd::from_raw_fd(fd))
            }
        }
    }.expect("Failed to create socket");


    let mut buffer = [0u8; 1500];
    
    let wan_iface = pnet::datalink::interfaces()
        .into_iter()
        .find(|iface| iface.name == *wan_name)
        .expect("Failed to find interface");
    println!("{:?}", wan_iface);
    let lan_iface = pnet::datalink::interfaces()
        .into_iter()
        .find(|iface| iface.name == *lan_name)
        .expect("Failed to find interface");
    
    socket::setsockopt(&ping_fd, socket::sockopt::BindToDevice, &OsString::from(lan_iface.name)).unwrap();

    unsafe {
        let res = libc::setsockopt(
            ping_fd.as_raw_fd(),
            libc::IPPROTO_RAW,
            libc::IPV6_CHECKSUM,
            &val as *const c_int as *const c_void,
            std::mem::size_of_val(&val) as u32,
        );
        Errno::result(res).map(drop)
    }.unwrap();
    val = 255;
    socket::setsockopt(&ping_fd, socket::sockopt::Ipv6MulticastHops, &val).unwrap();
    let filter = [0xff; 8];
    unsafe {
        let res = libc::setsockopt(
            ping_fd.as_raw_fd(),
            libc::IPPROTO_ICMPV6,
            1, // ICMPV6_FILTER
            filter.as_ptr() as *const c_void,
            std::mem::size_of_val(&filter) as u32,
        );
        Errno::result(res).map(drop)
    }.unwrap();
    loop {
        let (read_len, _) = socket::recvfrom::<LinkAddr>(socket_fd.as_raw_fd(), &mut buffer).unwrap();

        let eth_packet = pnet::packet::ethernet::EthernetPacket::new(&buffer[..read_len]).unwrap();
        if eth_packet.get_source() == wan_iface.mac.unwrap(){

            let mut ns = pnet::packet::icmpv6::ndp::MutableNeighborSolicitPacket::new(&mut buffer[14+40..read_len]).unwrap();
            // println!("{:?}",ns);
            // ns.set_options(&[]);
            ns.set_options(&[NdpOption{option_type:icmpv6::ndp::NdpOptionTypes::SourceLLAddr, length:1, data: lan_iface.mac.unwrap().octets().to_vec()}]);
            // println!("{:?}",ns);
            let dest = SockaddrIn6::from(
                SocketAddrV6::new(ns.get_target_addr(), 0, 0, 0)
            );
            ns.set_checksum(0xffff);

            // Dirty hack to send packet to the correct interface
            Command::new("sh").arg("-c").arg(format!("ip -6 route add {} dev {} metric 1023",ns.get_target_addr().to_string(),lan_name)).output().unwrap();
            socket::sendto(ping_fd.as_raw_fd(), ns.packet(),&dest, MsgFlags::empty()).unwrap();
            Command::new("sh").arg("-c").arg(format!("ip -6 route del {} dev {} metric 1023",ns.get_target_addr().to_string(),lan_name)).output().unwrap();
            // println!("{:?}",ns)
        }

    }


}
