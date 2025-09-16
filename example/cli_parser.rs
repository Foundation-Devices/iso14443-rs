use clap::Parser;
use hex::FromHex;
use iso14443::type_a::Command;

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    cmd: String,
    ans: String,
}

fn main() {
    let args = Args::parse();

    let cmd = Vec::<u8>::from_hex(&args.cmd).unwrap();
    let ans = Vec::<u8>::from_hex(&args.ans).unwrap();

    let cmd = Command::try_from(cmd.as_slice()).unwrap();
    let ans = cmd.parse_answer(&ans).unwrap();
    println!("cmd: {:02x?}", cmd);
    println!("ans: {:02x?}", ans);
}
