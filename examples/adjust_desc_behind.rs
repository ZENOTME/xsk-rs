use packet::ether::Packet;
use std::{convert::TryInto, io::Write, net::Ipv4Addr, thread};
use tokio::runtime::Runtime;
use xsk_rs::{
    config::{SocketConfig, UmemConfig},
    Socket, Umem,
};

#[allow(dead_code)]
mod setup;
use setup::{util, veth_setup, LinkIpAddr, PacketGenerator, VethDevConfig, ETHERNET_PACKET};

fn hello_xdp(dev1: (VethDevConfig, PacketGenerator), dev2: (VethDevConfig, PacketGenerator)) {
    // This UMEM will be shared between both sockets.
    let mut builder = UmemConfig::builder();
    builder.frame_headroom(16);

    let (umem, mut descs) = Umem::new(builder.build().unwrap(), 32.try_into().unwrap(), false)
        .expect("failed to create UMEM");

    // Bind an AF_XDP socket to the interface named `xsk_dev1`, on
    // queue 0.
    let (mut dev1_tx_q, _dev1_rx_q, dev1_fq_and_cq) = Socket::new(
        SocketConfig::default(),
        &umem,
        &dev1.0.if_name().parse().unwrap(),
        0,
    )
    .expect("failed to create dev1 socket");

    let (_dev1_fq, mut dev1_cq) = dev1_fq_and_cq.expect("missing dev1 fill queue and comp queue");

    // Bind an AF_XDP socket to the interface named `xsk_dev2`, on
    // queue 0. Also uses the UMEM above.
    let (_dev2_tx_q, mut dev2_rx_q, dev2_fq_and_cq) = Socket::new(
        SocketConfig::default(),
        &umem,
        &dev2.0.if_name().parse().unwrap(),
        0,
    )
    .expect("failed to create dev2 socket");

    let (mut dev2_fq, _dev2_cq) = dev2_fq_and_cq.expect("missing dev2 fill queue and comp queue");

    // Just split the UMEM frames between the two sockets for
    // convenience.
    let (dev1_descs, mut dev2_descs) = descs.split_at_mut(16);

    // 1. Add frames to dev2's fill queue so we are ready to receive
    // some packets.
    println!("fill at {}", dev2_descs[0].addr());
    let fill_addr = dev2_descs[0].addr();
    unsafe {
        dev2_fq.produce(&dev2_descs);
    }

    // 2. Write to the UMEM.
    println!("before send at {}", dev1_descs[4].addr());
    let before_addr = dev1_descs[4].addr();
    unsafe {
        // write payload
        umem.data_mut(&mut dev1_descs[4])
            .cursor()
            .write_all(&ETHERNET_PACKET)
            .expect("failed writing packet to frame");
        umem.data_mut(&mut dev1_descs[4])
            .cursor()
            .write_all(&ETHERNET_PACKET)
            .expect("failed writing packet to frame")
    }
    umem.adjust_addr(&mut dev1_descs[4], ETHERNET_PACKET.len() as i32);
    let after_addr = dev1_descs[4].addr();
    assert!(before_addr == after_addr - ETHERNET_PACKET.len());
    assert!(dev1_descs[4].lengths().data() == ETHERNET_PACKET.len());
    assert!(unsafe { umem.data(&dev1_descs[4]).contents() } == ETHERNET_PACKET);

    // 3. Submit the frame to the kernel for transmission.
    println!("sending packet");

    unsafe {
        dev1_tx_q.produce_and_wakeup(&dev1_descs[4..5]).unwrap();
    }

    unsafe {
        dev1_cq.consume_one(&mut dev1_descs[1]);
    }

    println!("cp {}", dev1_descs[1].addr());
    let cp_addr = dev1_descs[1].addr();
    assert!(cp_addr == before_addr);

    // 4. Read on dev2.
    let pkts_recvd = unsafe { dev2_rx_q.poll_and_consume(&mut dev2_descs, 100).unwrap() };

    // 5. Confirm that one of the packets we received matches what we expect.
    for recv_desc in dev2_descs.iter().take(pkts_recvd) {
        println!("receive at {}", recv_desc.addr());
        let receive_addr = recv_desc.addr();
        assert!(receive_addr == fill_addr);

        let data = unsafe { umem.data(recv_desc) };

        if data.contents() == &ETHERNET_PACKET {
            println!("received packet!");
            return;
        }
    }

    panic!("no matching packets received")
}

fn main() {
    let dev1_config = VethDevConfig {
        if_name: "xsk_test_dev1".into(),
        addr: [0xf6, 0xe0, 0xf6, 0xc9, 0x60, 0x0a],
        ip_addr: LinkIpAddr::new(Ipv4Addr::new(192, 168, 69, 1), 24),
    };

    let dev2_config = VethDevConfig {
        if_name: "xsk_test_dev2".into(),
        addr: [0x4a, 0xf1, 0x30, 0xeb, 0x0d, 0x31],
        ip_addr: LinkIpAddr::new(Ipv4Addr::new(192, 168, 69, 1), 24),
    };

    // We'll keep track of ctrl+c events but not let them kill the process
    // immediately as we may need to clean up the veth pair.
    let ctrl_c_events = util::ctrl_channel().unwrap();

    let (complete_tx, complete_rx) = crossbeam_channel::bounded(1);

    let runtime = Runtime::new().unwrap();

    let example_handle = thread::spawn(move || {
        let res = runtime.block_on(veth_setup::run_with_veth_pair(
            dev1_config,
            dev2_config,
            hello_xdp,
        ));

        let _ = complete_tx.send(());

        res
    });

    // Wait for either the example to finish or for a ctrl+c event to occur.
    crossbeam_channel::select! {
        recv(complete_rx) -> _ => {
        },
        recv(ctrl_c_events) -> _ => {
            println!("SIGINT received");
        }
    }

    example_handle.join().unwrap().unwrap();
}