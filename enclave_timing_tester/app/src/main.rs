use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;

fn main() -> std::io::Result<()> {
    let mut stream = BufReader::new(TcpStream::connect("cat")?);
    let mut b = BufReader::new(&mut stream);

    for _i in 0..30000 {
        stream.get_mut().write_all(b"\n")?;

        let mut echo = String::new();
        b.read_line(&mut echo)?;
        // println!("{}", echo);
    }
    println!("Process finished!");
    Ok(())
}
