use pwhash::{bcrypt, bsdi_crypt, md5_crypt, sha1_crypt, sha256_crypt, sha512_crypt, unix, unix_crypt};

use std::io;
use clap::{Args, Parser, Subcommand, ValueEnum};

#[derive(Debug, Parser)]
#[command(author, version, about)]
#[command(infer_subcommands = true)]
#[command(args_conflicts_with_subcommands = true)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    #[command(flatten)]
    generate: GenerateArgs,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Generate(GenerateArgs),
    Validate(ValidateArgs),
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Scheme {
    Bcrypt,
    Bsdi,
    Crypt,
    Md5,
    Sha1,
    Sha256,
    Sha512,
}

#[derive(Clone, Debug, Args)]
struct GenerateArgs {
    #[arg(long, short)]
    password: Option<String>,
    #[arg(long, short, value_enum, default_value_t = Scheme::Sha512)]
    scheme: Scheme,
}

#[derive(Clone, Debug, Args)]
struct ValidateArgs {
    #[arg(long, short)]
    password: Option<String>,
    hash: String
}

#[allow(deprecated)]
fn generate(GenerateArgs{ password, scheme }: GenerateArgs) -> io::Result<()> {
    let pw = prompt_password(password)?;

    let hash = match scheme {
	Scheme::Bcrypt => bcrypt::hash(pw),
	Scheme::Bsdi => bsdi_crypt::hash(pw),
	Scheme::Crypt => unix_crypt::hash(pw),
	Scheme::Md5 => md5_crypt::hash(pw),
	Scheme::Sha1 => sha1_crypt::hash(pw),
	Scheme::Sha256 => sha256_crypt::hash(pw),
	Scheme::Sha512 => sha512_crypt::hash(pw),
    };
    println!("{}", hash.unwrap());
    Ok(())
}

fn validate(ValidateArgs{ password, hash }: ValidateArgs) -> io::Result<()> {
    let pw = prompt_password(password)?;
    if unix::verify(pw, &hash) {
	println!("valid");
    } else {
	println!("not valid");
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let cmd = cli.command.unwrap_or(Commands::Generate(cli.generate));
    match cmd {
	Commands::Generate(args) => generate(args)?,
	Commands::Validate(args) => validate(args)?,
    };
    Ok(())
}

fn prompt_password(password: Option<String>) -> io::Result<String> {
    match password {
	Some(pw) => Ok(pw),
	None => loop {
	    let pw = rpassword::prompt_password("Enter new password: ")?;
	    let confirmed = rpassword::prompt_password("Retype new password: ")?;
	    if pw == confirmed {
		return Ok(pw)
	    }
	    println!("Error: Passwords don't match!")
	}
    }
}
