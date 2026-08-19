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
    #[arg(
        short,
        long,
        help = "Input has no CRC_A (already validated and stripped by hardware)"
    )]
    no_crc: bool,
    #[arg(short, long, help = "Parse as ISO14443-4 block format")]
    block: bool,
}

fn main() {
    let args = Args::parse();

    let cmd = Vec::<u8>::from_hex(&args.command).unwrap();
    let ans = Vec::<u8>::from_hex(args.answer.unwrap_or_default()).unwrap();

    // Without --no-crc the input is raw wire data and its CRC_A must check
    // out; with it, the bytes are taken as already verified and CRC-free.
    if args.block {
        let block = if args.no_crc {
            Block::from_crc_verified(&cmd)
        } else {
            Block::try_from(cmd.as_slice())
        };
        let block = block.unwrap_or_else(|e| panic!("{:02x?}", e));
        println!("command: {:#02x?}", block);
        if !ans.is_empty() {
            let response_block = if args.no_crc {
                Block::from_crc_verified(&ans)
            } else {
                Block::try_from(ans.as_slice())
            };
            let response_block = response_block.unwrap_or_else(|e| panic!("{:02x?}", e));
            println!("answer: {:#02x?}", response_block);
        }
    } else {
        let cmd = if args.no_crc {
            Command::from_crc_verified(&cmd)
        } else {
            Command::try_from(cmd.as_slice())
        };
        let cmd = cmd.unwrap_or_else(|e| panic!("{:02x?}", e));
        println!("command: {:#02x?}", cmd);
        if !ans.is_empty() {
            let ans = if args.no_crc {
                cmd.parse_answer_crc_verified(&ans)
            } else {
                cmd.parse_answer(&ans)
            };
            let ans = ans.unwrap_or_else(|e| panic!("{:02x?}", e));
            println!("answer: {:#02x?}", ans);
        }
    }
}
