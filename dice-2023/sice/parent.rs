use std::io::Read;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

fn main() {
	let mut child = Command::new("./child")
		.stdout(Stdio::piped())
		.spawn()
		.unwrap();

	thread::sleep(Duration::from_secs(10));

	let mut input_buf = [0u8; 100000];
	let mut stdout = child.stdout.take().unwrap();
	stdout.read(&mut input_buf).unwrap();

	child.wait().unwrap();
}