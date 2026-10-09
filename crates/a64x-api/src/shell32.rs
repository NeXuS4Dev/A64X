//! SHELL32 `CommandLineToArgvW`, and the command-line splitter shared with
//! the CRT's `argv` construction.
//!
//! The splitting rules are the Microsoft C runtime rules: arguments are
//! separated by blanks outside quotes; `2n` backslashes before a quote give
//! `n` backslashes and toggle quoting; `2n+1` give `n` backslashes and a
//! literal quote; a doubled quote inside quotes is a literal quote.

use crate::{heap, reg, ApiCtx, ApiDef};
use a64x_core::Result;

/// Split a command line (ANSI bytes, NUL-terminated or not) into arguments.
/// argv[0] is the program name, as parsed by the same rules. An empty
/// command line yields the program name only.
pub(crate) fn parse_command_line(cmd: &[u8]) -> Vec<Vec<u8>> {
    let s: &[u8] = cmd.split(|&b| b == 0).next().unwrap_or(&[]);
    let n = s.len();
    let mut args: Vec<Vec<u8>> = Vec::new();
    let mut i = 0usize;
    while i < n {
        // skip blanks between arguments (argv[0] starts at the first byte)
        if !args.is_empty() {
            while i < n && (s[i] == b' ' || s[i] == b'\t') {
                i += 1;
            }
            if i >= n {
                break;
            }
        }
        let mut arg = Vec::new();
        let mut in_quotes = false;
        loop {
            if i >= n {
                break;
            }
            if s[i] == b'\\' {
                let start = i;
                while i < n && s[i] == b'\\' {
                    i += 1;
                }
                let count = i - start;
                if i < n && s[i] == b'"' {
                    for _ in 0..count / 2 {
                        arg.push(b'\\');
                    }
                    if count % 2 == 1 {
                        arg.push(b'"');
                        i += 1;
                    }
                } else {
                    arg.extend(std::iter::repeat_n(b'\\', count));
                }
                continue;
            }
            if s[i] == b'"' {
                if in_quotes && s.get(i + 1) == Some(&b'"') {
                    arg.push(b'"');
                    i += 2;
                    continue;
                }
                in_quotes = !in_quotes;
                i += 1;
                continue;
            }
            if !in_quotes && (s[i] == b' ' || s[i] == b'\t') {
                break;
            }
            arg.push(s[i]);
            i += 1;
        }
        args.push(arg);
    }
    if args.is_empty() {
        args.push(b"guest.exe".to_vec());
    }
    args
}

/// `CommandLineToArgvW(lpCmdLine, pNumArgs)`: returns one heap block holding
/// the pointer array followed by the wide strings (free with LocalFree).
fn command_line_to_argv_w(ctx: &mut ApiCtx) -> Result<()> {
    let cmd = ctx.wstr(ctx.a(0))?;
    let text = String::from_utf16_lossy(&cmd);
    let args = parse_command_line(text.as_bytes());
    let args_w: Vec<Vec<u16>> = args
        .iter()
        .map(|a| String::from_utf8_lossy(a).encode_utf16().collect())
        .collect();
    let ptr_bytes = 8 * (args_w.len() as u64 + 1);
    let total: u64 = ptr_bytes + args_w.iter().map(|a| 2 * (a.len() as u64 + 1)).sum::<u64>();
    let block = heap::alloc(ctx, 0, total, 16, false)?;
    if block == 0 {
        ctx.set_last_error(8);
        ctx.ret(0);
        return Ok(());
    }
    let mut str_at = block + ptr_bytes;
    for (i, a) in args_w.iter().enumerate() {
        ctx.wr(block + 8 * i as u64, 8, str_at)?;
        ctx.put_wide(str_at, a)?;
        ctx.wr(str_at + 2 * a.len() as u64, 2, 0)?;
        str_at += 2 * (a.len() as u64 + 1);
    }
    ctx.wr(block + 8 * args_w.len() as u64, 8, 0)?;
    let np = ctx.a(1);
    if np != 0 {
        ctx.wr(np, 4, args_w.len() as u64)?;
    }
    ctx.ret(block);
    Ok(())
}

pub(crate) fn register(v: &mut Vec<ApiDef>) {
    reg!(v, "shell32",
        "CommandLineToArgvW" => command_line_to_argv_w,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn split(s: &str) -> Vec<String> {
        parse_command_line(s.as_bytes())
            .into_iter()
            .map(|a| String::from_utf8(a).unwrap())
            .collect()
    }

    #[test]
    fn quotes_and_spaces() {
        assert_eq!(split("prog a \"b c\" d"), vec!["prog", "a", "b c", "d"]);
        assert_eq!(split("prog \"\""), vec!["prog", ""]);
        assert_eq!(split("prog \"a\"\"b\""), vec!["prog", "a\"b"]);
    }

    #[test]
    fn backslash_rules() {
        assert_eq!(split(r#"p "a\"b""#), vec!["p", "a\"b"]);
        assert_eq!(split(r"p a\\b"), vec!["p", r"a\\b"]);
        assert_eq!(split(r#"p "C:\dir\\" x"#), vec!["p", r"C:\dir\", "x"]);
    }

    #[test]
    fn empty_line_gives_program_name() {
        assert_eq!(split(""), vec!["guest.exe"]);
    }
}
