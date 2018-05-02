extern crate fsm;
extern crate pcap;
extern crate json;
use fsm::EnumTag;
use fsm::Machine;
use pcap::{Device, Capture};
use std::io::prelude::*;
use std::net::TcpStream;

// states and events must be C-like enums (copyable and easily converted to primitives)
#[derive(Copy, Clone)]
enum State {
    Locked,
    Detected_Level1,
    Detected_Level2,
    Detected_Level3,
    Confirmed,
}

#[derive(Copy, Clone)]
enum Event {
    PPTP_Start_Control_Connection_Request,
    PPTP_Start_Control_Connection_Reply,
    PPTP_Outgoing_Call_Request,
    PPTP_Outgoing_Call_Reply,
}

// implement the EnumTag trait for states and events

impl EnumTag for State {
    fn tag_number(&self) -> usize {
        *self as usize
    }
    fn max_tag_number() -> usize {
        State::Confirmed as usize
    }
}

impl EnumTag for Event {
    fn tag_number(&self) -> usize {
        *self as usize
    }
    fn max_tag_number() -> usize {
       Event::PPTP_Outgoing_Call_Reply as usize
    }
}

fn main() {
    //define FSM
    let mut machine = Machine::new(State::Locked);
   machine.add_transition(
       State::Locked,
       Event::PPTP_Start_Control_Connection_Request,
       State::Detected_Level1,
       |_, _| println!("PPTP-Start-Control-Connection-Request detected!"),
   );
   machine.add_transition(
       State::Detected_Level1,
       Event::PPTP_Start_Control_Connection_Reply,
       State::Detected_Level2,
       |_, _| println!("PPTP-Start-Control-Connection-Reply detected!"),
   );
   machine.add_transition(
       State::Detected_Level2,
       Event::PPTP_Outgoing_Call_Request,
       State::Detected_Level3,
       |_, _| println!("PPTP-Outgoing-Call-Request detected!"),
   );
   machine.add_transition(
       State::Detected_Level3,
       Event::PPTP_Outgoing_Call_Reply,
       State::Confirmed,
       |_, _| println!("PPTP-Outgoing-Call-Reply detected!"),
   );

	//注意网卡可能需要开启混杂模式.
    let main_device = Device::lookup().unwrap();
    let mut cap = Capture::from_device(main_device).unwrap().promisc(true).open().unwrap();
	cap.filter("tcp").unwrap(); 	//use BPF filter before.
    while let Ok(packet) = cap.next() {
		let data = packet.data;
  	let src_ip = format!("{}.{}.{}.{}", data[26], data[27], data[28], data[29]);
  	let dst_ip = format!("{}.{}.{}.{}", data[30], data[31], data[32], data[33]);
  	let mut tuple = json::JsonValue::new_object();
		tuple["src_ip"] = src_ip.into();
		tuple["dst_ip"] = dst_ip.into();
		tuple["event"] = json::Null;
		if data.len() > 56 {
	  		let (_, data_right) = data.split_at(56);
	  		if data_right.starts_with(&[0x00, 0x01, 0x1a, 0x2b, 0x3c, 0x4d, 0x00, 0x01]){
      			machine.on_event(Event::PPTP_Start_Control_Connection_Request);
	  		};
	  		if data_right.starts_with(&[0x00, 0x01, 0x1a, 0x2b, 0x3c, 0x4d, 0x00, 0x02]){
      			machine.on_event(Event::PPTP_Start_Control_Connection_Reply);
	  		};
	  		if data_right.starts_with(&[0x00, 0x01, 0x1a, 0x2b, 0x3c, 0x4d, 0x00, 0x07]){
      			machine.on_event(Event::PPTP_Outgoing_Call_Request);
	  		};
	  		if data_right.starts_with(&[0x00, 0x01, 0x1a, 0x2b, 0x3c, 0x4d, 0x00, 0x08]){
      			machine.on_event(Event::PPTP_Outgoing_Call_Reply);
                //ban ip
                tuple["event"] = "PPTP VPN dial up detected!".into();
                println!("sending json:{}", tuple);
                {
                    let mut stream = TcpStream::connect("127.0.0.1:23333").unwrap();
                    let _ = stream.write(json::stringify(tuple).as_bytes());
                }
	  		};
		};
        /* detect GRE Encapsulation
        if data[23] == 0x2f{
			tuple["event"] = "GRE-Encapsulation".into();
		};
        */
    }
}
