use clap::Parser;
use hex::FromHex;
use iso14443::type_a::Command;

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    #[arg(short, long)]
    command: String,
    #[arg(short, long)]
    answer: Option<String>,
    #[arg(short, long)]
    no_crc: bool,
}

fn main() {
    let args = Args::parse();

    let mut cmd = Vec::<u8>::from_hex(&args.command).unwrap();
    let mut ans = Vec::<u8>::from_hex(&args.answer.unwrap_or_default()).unwrap();

    if args.no_crc {
        // add a fake crc
        cmd.extend_from_slice(&[0, 0]);
    }
    let cmd = Command::try_from(cmd.as_slice()).unwrap_or_else(|e| panic!("{:02x?}", e));
    println!("command: {:02x?}", cmd);
    if !ans.is_empty() {
        if args.no_crc {
            // add a fake crc
            ans.extend_from_slice(&[0, 0]);
        }
        let ans = cmd
            .parse_answer(&ans)
            .unwrap_or_else(|e| panic!("{:02x?}", e));
        println!("answer: {:02x?}", ans);
    }
}
