use clap::Parser;
use hex::FromHex;
use iso14443::type_a::{Block, Command};

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    #[arg(short, long)]
    command: String,
    #[arg(short, long)]
    answer: Option<String>,
    #[arg(short, long)]
    no_crc: bool,
    #[arg(short, long, help = "Parse as ISO14443-4 block format")]
    block: bool,
}

fn main() {
    let args = Args::parse();

    let mut cmd = Vec::<u8>::from_hex(&args.command).unwrap();
    let mut ans = Vec::<u8>::from_hex(&args.answer.unwrap_or_default()).unwrap();

    if args.no_crc {
        // add a fake crc
        cmd.extend_from_slice(&[0, 0]);
    }
    if args.no_crc {
        ans.extend_from_slice(&[0, 0]);
    }

    // Parse as command format
    if args.block {
        let block = Block::try_from(cmd.as_slice()).unwrap_or_else(|e| panic!("{:02x?}", e));
        println!("command: {:#02x?}", block);
        if ans.len() > 2 {
            let response_block =
                Block::try_from(ans.as_slice()).unwrap_or_else(|e| panic!("{:02x?}", e));
            println!("answer: {:#02x?}", response_block);
        }
    } else {
        let cmd = Command::try_from(cmd.as_slice()).unwrap_or_else(|e| panic!("{:02x?}", e));
        println!("command: {:#02x?}", cmd);
        if ans.len() > 2 {
            let ans = cmd
                .parse_answer(&ans)
                .unwrap_or_else(|e| panic!("{:02x?}", e));
            println!("answer: {:#02x?}", ans);
        }
    }
}
