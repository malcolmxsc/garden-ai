use netlink_packet_route::link::{LinkMessage, LinkFlags};

pub fn test() {
    let mut msg = LinkMessage::default();
    msg.header.index = 1;
    msg.header.flags = LinkFlags::Up;
    msg.header.change_mask = LinkFlags::Up;
}
