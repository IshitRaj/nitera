//! Minimal end-to-end demo of Nitera: load a policy, wire up an approval
//! handler for anything marked `ask`, then create, read, write, and delete files,
//! logging whatever the policy decides rather than crashing on it.
//!
//! Run with: cargo run --example playground

use nitera::{ApprovalDecision, Nitera};
use std::io::{self, Write};

fn main() {
    let file = "playground/test.txt";
    let created_file = "playground/created.txt";
    let created_directory = "playground/logs";

    let nitera = Nitera::load("examples/playground.nitera")
        .expect("failed to load nitera policy")
        .with_approval_handler(prompt_for_approval);

    println!("Nitera playground loaded successfully.\n");

    match nitera.create(created_file, "Created by Nitera!") {
        Ok(()) => println!("[create file] succeeded"),
        Err(err) => println!("[create file] {err}"),
    }

    match nitera.create(created_file, "Created by Nitera!") {
        Ok(()) => println!("[create file existing] unexpectedly succeeded"),
        Err(err) => println!("[create file existing] {err}"),
    }

    match nitera.create_dir(created_directory) {
        Ok(()) => println!("[create dir] succeeded"),
        Err(err) => println!("[create dir] {err}"),
    }

    match nitera.read(file) {
        Ok(content) => println!("[read] succeeded -> {}", String::from_utf8_lossy(&content)),
        Err(err) => println!("[read] {err}"),
    }

    match nitera.write(file, "Hello from Nitera!") {
        Ok(()) => println!("[write] succeeded"),
        Err(err) => println!("[write] {err}"),
    }

    match nitera.read(file) {
        Ok(content) => println!(
            "[read after write] succeeded -> {}",
            String::from_utf8_lossy(&content)
        ),
        Err(err) => println!("[read after write] {err}"),
    }

    match nitera.delete(file) {
        Ok(()) => println!("[delete] succeeded"),
        Err(err) => println!("[delete] {err}"),
    }

    match nitera.execute("echo", ["Hello from Nitera!"], ".") {
        Ok(output) => println!(
            "[execute] succeeded -> {}",
            String::from_utf8_lossy(&output.stdout).trim()
        ),
        Err(err) => println!("[execute] {err}"),
    }

    match nitera.execute("rm", [file], ".") {
        Ok(output) => println!(
            "[execute rm] succeeded -> {}",
            String::from_utf8_lossy(&output.stdout).trim()
        ),
        Err(err) => println!("[execute rm] {err}"),
    }
}

/// Prompts in the terminal whenever a policy rule is marked `ask`.
fn prompt_for_approval(request: &nitera::NiteraRequest) -> ApprovalDecision {
    print!("Approve: {request}? [y/N] ");
    io::stdout().flush().ok();

    let mut input = String::new();
    io::stdin().read_line(&mut input).ok();

    if input.trim().eq_ignore_ascii_case("y") {
        ApprovalDecision::Approved
    } else {
        ApprovalDecision::Denied
    }
}
