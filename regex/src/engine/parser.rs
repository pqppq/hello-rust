//! parse regex and transform into AST
use std::{
    error::Error,
    fmt::{self, Display},
    mem::take,
};

/// AST type
#[derive(Debug, PartialEq, Eq)]
pub enum AST {
    Char(char),             // one character
    Plus(Box<AST>),         // +
    Star(Box<AST>),         // *
    Question(Box<AST>),     // ?
    Or(Box<AST>, Box<AST>), // |
    Seq(Vec<AST>),          // sequence of regex
}

enum PSQ {
    Plus,
    Star,
    Question,
}

/// parse error
#[derive(Debug)]
pub enum ParseError {
    InvalidEscape(usize, char), // invalid escape sequence
    InvalidRightParen(usize),   // missing )
    NoPrev(usize),              // no expression before + | * ?
    NoRightParen,               // missing (
    Empty,
}

/// impl Display trait for display parse error
impl Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::InvalidEscape(pos, c) => {
                write!(f, "ParseError: invalid escape: pos = {pos}, char = '{c}'")
            }
            ParseError::InvalidRightParen(pos) => {
                write!(f, "ParseError: invalid right parenthesis: pos = {pos}")
            }
            ParseError::NoPrev(pos) => {
                write!(f, "ParseError: no previous expresison: pos = {pos}")
            }
            ParseError::NoRightParen => {
                write!(f, "ParseError: no right parenthesis")
            }
            ParseError::Empty => write!(f, "ParseError: empty expression"),
        }
    }
}

impl Error for ParseError {}

/// transform + * ? into AST
fn parse_plus_star_question(
    seq: &mut Vec<AST>,
    ast_type: PSQ,
    pos: usize,
) -> Result<(), ParseError> {
    if let Some(prev) = seq.pop() {
        let ast = match ast_type {
            PSQ::Plus => AST::Plus(Box::new(prev)),
            PSQ::Star => AST::Star(Box::new(prev)),
            PSQ::Question => AST::Question(Box::new(prev)),
        };
        seq.push(ast);
        Ok(())
    } else {
        Err(ParseError::NoPrev(pos))
    }
}

// parse escape sequence
fn parse_escape(pos: usize, c: char) -> Result<AST, ParseError> {
    match c {
        '\\' | '(' | ')' | '|' | '+' | '*' | '?' => Ok(AST::Char(c)),
        _ => {
            let err = ParseError::InvalidEscape(pos, c);
            Err(err)
        }
    }
}

// transform seq_or into OR AST
fn fold_or(mut seq_or: Vec<AST>) -> Option<AST> {
    if seq_or.len() > 1 {
        let mut ast = seq_or.pop().unwrap();
        seq_or.reverse();
        for s in seq_or {
            ast = AST::Or(Box::new(s), Box::new(ast));
        }
        Some(ast)
    } else {
        // if seq_or has one AST, return that value
        seq_or.pop()
    }
}

/// transform regex into AST
pub fn parse(expr: &str) -> Result<AST, ParseError> {
    enum ParseState {
        Char,
        Escape,
    }

    let mut seq = Vec::new(); // context
    let mut seq_or = Vec::new(); // OR context
    let mut stack = Vec::new(); // context stack
    let mut state = ParseState::Char; // current state

    for (i, c) in expr.chars().enumerate() {
        match &state {
            ParseState::Char => {
                match c {
                    '+' => parse_plus_star_question(&mut seq, PSQ::Plus, i)?,
                    '*' => parse_plus_star_question(&mut seq, PSQ::Star, i)?,
                    '?' => parse_plus_star_question(&mut seq, PSQ::Question, i)?,
                    '(' => {
                        // push current context to stack
                        // clean up current context
                        // takeは引数の値を返して、その引数を型のデフォルト値にする
                        let prev = take(&mut seq);
                        let prev_or = take(&mut seq_or);
                        stack.push((prev, prev_or));
                    }
                    ')' => {
                        // pop context from stack
                        if let Some((mut prev, prev_or)) = stack.pop() {
                            if !seq.is_empty() {
                                seq_or.push(AST::Seq(seq));
                            }
                            // create Or
                            if let Some(ast) = fold_or(seq_or) {
                                prev.push(ast);
                            }
                            // swap context
                            seq = prev;
                            seq_or = prev_or;
                        } else {
                            // return Err(ParseError::InvalidRightParen(i));
                        }
                    }
                    '|' => {
                        if seq.is_empty() {
                            // "||", "(|abc)", etc.
                            return Err(ParseError::NoPrev(i));
                        } else {
                            let prev = take(&mut seq);
                            seq_or.push(AST::Seq(prev))
                        }
                    }
                    '\\' => state = ParseState::Escape,
                    _ => seq.push(AST::Char(c)),
                };
            }
            ParseState::Escape => {
                // process escape sequence
                let ast = parse_escape(i, c)?;
                seq.push(ast);
                state = ParseState::Char;
            }
        }
    }

    if !stack.is_empty() {
        return Err(ParseError::NoRightParen);
    }

    if !seq.is_empty() {
        seq_or.push(AST::Seq(seq));
    }

    if let Some(ast) = fold_or(seq_or) {
        Ok(ast)
    } else {
        Err(ParseError::Empty)
    }
}

#[cfg(test)]
mod tests {
    use crate::engine::parser::{parse, AST};

    #[test]
    fn parse_test() {
        // simple cases
        let expr: &str = "ab";
        let expect: AST = AST::Seq(vec![AST::Char('a'), AST::Char('b')]);
        assert_eq!(expect, parse(expr).unwrap());

        let expr: &str = "ab+";
        let expect: AST = AST::Seq(vec![AST::Char('a'), AST::Plus(Box::new(AST::Char('b')))]);
        assert_eq!(expect, parse(expr).unwrap());

        let expr: &str = "ab*";
        let expect: AST = AST::Seq(vec![AST::Char('a'), AST::Star(Box::new(AST::Char('b')))]);
        assert_eq!(expect, parse(expr).unwrap());

        let expr: &str = "ab?";
        let expect: AST = AST::Seq(vec![
            AST::Char('a'),
            AST::Question(Box::new(AST::Char('b'))),
        ]);
        assert_eq!(expect, parse(expr).unwrap());

        let expr: &str = "a|b";
        let expect: AST = AST::Or(
            Box::new(AST::Seq(vec![AST::Char('a')])),
            Box::new(AST::Seq(vec![AST::Char('b')])),
        );
        assert_eq!(expect, parse(expr).unwrap());

        // complex cases
        let expr: &str = "(a*)*";
        let expect: AST = AST::Seq(
            vec![AST::Star(Box::new(AST::Seq(
                        vec![AST::Star(Box::new(AST::Char('a')))]
                    )))]);
        assert_eq!(expect, parse(expr).unwrap());
    }
}
