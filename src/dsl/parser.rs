#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[allow(missing_docs)]
pub enum Expr {
    Integer(i64),
    String(String),
    Identifier(String),
    UnaryNot(Box<Expr>),
    Binary {
        left: Box<Expr>,
        op: BinaryOp,
        right: Box<Expr>,
    },
    List(Vec<Expr>),
    FunctionCall {
        name: String,
        args: Vec<Expr>,
    },
    MethodCall {
        receiver: Box<Expr>,
        name: String,
        args: Vec<Expr>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[allow(missing_docs)]
pub enum BinaryOp {
    Add,
    Sub,
    Mul,
    Div,
    Eq,
    Ne,
    Gt,
    Lt,
    Ge,
    Le,
    And,
    Or,
}

#[derive(Debug, Clone, PartialEq)]
enum Token {
    Identifier(String),
    Integer(i64),
    String(String),
    LParen,
    RParen,
    Comma,
    LBracket,
    RBracket,
    Dot,
    Plus,
    Minus,
    Star,
    Slash,
    Not,
    EqEq,
    NotEq,
    Gt,
    Lt,
    Ge,
    Le,
    AndAnd,
    OrOr,
}

struct Lexer<'a> {
    input: &'a str,
    pos: usize,
}

impl<'a> Lexer<'a> {
    fn new(input: &'a str) -> Self {
        Self { input, pos: 0 }
    }

    fn next_token(&mut self) -> Option<Token> {
        self.skip_whitespace();
        let rest = self.input.get(self.pos..)?;
        let mut chars = rest.char_indices();
        let (_, ch) = chars.next()?;

        match ch {
            '(' => {
                self.pos += 1;
                Some(Token::LParen)
            }
            ')' => {
                self.pos += 1;
                Some(Token::RParen)
            }
            ',' => {
                self.pos += 1;
                Some(Token::Comma)
            }
            '[' => {
                self.pos += 1;
                Some(Token::LBracket)
            }
            ']' => {
                self.pos += 1;
                Some(Token::RBracket)
            }
            '+' => {
                self.pos += 1;
                Some(Token::Plus)
            }
            '-' => {
                self.pos += 1;
                Some(Token::Minus)
            }
            '*' => {
                self.pos += 1;
                Some(Token::Star)
            }
            '/' => {
                self.pos += 1;
                Some(Token::Slash)
            }
            '.' => {
                self.pos += 1;
                Some(Token::Dot)
            }
            '!' => {
                if rest.starts_with("!=") {
                    self.pos += 2;
                    Some(Token::NotEq)
                } else {
                    self.pos += 1;
                    Some(Token::Not)
                }
            }
            '=' => {
                if rest.starts_with("==") {
                    self.pos += 2;
                    Some(Token::EqEq)
                } else {
                    None
                }
            }
            '>' => {
                if rest.starts_with(">=") {
                    self.pos += 2;
                    Some(Token::Ge)
                } else {
                    self.pos += 1;
                    Some(Token::Gt)
                }
            }
            '<' => {
                if rest.starts_with("<=") {
                    self.pos += 2;
                    Some(Token::Le)
                } else {
                    self.pos += 1;
                    Some(Token::Lt)
                }
            }
            '&' => {
                if rest.starts_with("&&") {
                    self.pos += 2;
                    Some(Token::AndAnd)
                } else {
                    None
                }
            }
            '|' => {
                if rest.starts_with("||") {
                    self.pos += 2;
                    Some(Token::OrOr)
                } else {
                    None
                }
            }
            '"' => self.lex_string('"'),
            '\'' => self.lex_string('\''),
            c if c.is_ascii_digit() => self.lex_integer(),
            c if is_ident_start(c) => Some(self.lex_identifier()),
            _ => None,
        }
    }

    fn skip_whitespace(&mut self) {
        while let Some(ch) = self.input[self.pos..].chars().next() {
            if ch.is_whitespace() {
                self.pos += ch.len_utf8();
            } else {
                break;
            }
        }
    }

    fn lex_integer(&mut self) -> Option<Token> {
        let start = self.pos;
        while let Some(ch) = self.input[self.pos..].chars().next() {
            if ch.is_ascii_digit() {
                self.pos += 1;
            } else {
                break;
            }
        }
        // An out-of-range literal must REJECT the expression, not silently
        // wrap to a default: `content_length == 99999999999999999999`
        // becoming `== 0` would invert the meaning of a security rule.
        let value = self.input[start..self.pos].parse().ok()?;
        Some(Token::Integer(value))
    }

    fn lex_identifier(&mut self) -> Token {
        let start = self.pos;
        while let Some(ch) = self.input[self.pos..].chars().next() {
            if is_ident_continue(ch) {
                self.pos += ch.len_utf8();
            } else {
                break;
            }
        }
        Token::Identifier(self.input[start..self.pos].to_string())
    }

    fn lex_string(&mut self, quote: char) -> Option<Token> {
        self.pos += 1;
        let mut value = String::new();

        while let Some(ch) = self.input[self.pos..].chars().next() {
            self.pos += ch.len_utf8();
            match ch {
                ch if ch == quote => return Some(Token::String(value)),
                '\\' => {
                    let escaped = self.input[self.pos..].chars().next()?;
                    self.pos += escaped.len_utf8();
                    match escaped {
                        '"' => value.push('"'),
                        '\'' => value.push('\''),
                        '\\' => value.push('\\'),
                        'n' => value.push('\n'),
                        'r' => value.push('\r'),
                        't' => value.push('\t'),
                        // Preserve unrecognized escapes verbatim (backslash +
                        // char) so regex metacharacters like \d, \w, \. survive
                        // into patterns passed to the regex() DSL function.
                        // Dropping the backslash silently corrupted every regex
                        // written with an escape (e.g. `\d+\.\d+` became `d+.d+`,
                        // matching nothing).
                        other => {
                            value.push('\\');
                            value.push(other);
                        }
                    }
                }
                other => value.push(other),
            }
        }

        None
    }
}

fn is_ident_start(ch: char) -> bool {
    ch.is_ascii_alphabetic() || ch == '_'
}

fn is_ident_continue(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_'
}

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
    valid: bool,
}

impl Parser {
    fn new(input: &str) -> Self {
        let mut lexer = Lexer::new(input);
        let mut tokens = Vec::new();
        let mut valid = true;
        while lexer.pos < input.len() {
            let start = lexer.pos;
            let Some(token) = lexer.next_token() else {
                valid = false;
                break;
            };
            tokens.push(token);
            if lexer.pos == start {
                valid = false;
                break;
            }
        }
        Self {
            tokens,
            pos: 0,
            valid,
        }
    }

    fn parse_expression(&mut self) -> Option<Expr> {
        if !self.valid {
            return None;
        }
        self.parse_or()
    }

    fn parse_or(&mut self) -> Option<Expr> {
        let mut expr = self.parse_and()?;
        while self.consume(&Token::OrOr) {
            let right = self.parse_and()?;
            expr = Expr::Binary {
                left: Box::new(expr),
                op: BinaryOp::Or,
                right: Box::new(right),
            };
        }
        Some(expr)
    }

    fn parse_and(&mut self) -> Option<Expr> {
        let mut expr = self.parse_comparison()?;
        while self.consume(&Token::AndAnd) {
            let right = self.parse_comparison()?;
            expr = Expr::Binary {
                left: Box::new(expr),
                op: BinaryOp::And,
                right: Box::new(right),
            };
        }
        Some(expr)
    }

    fn parse_comparison(&mut self) -> Option<Expr> {
        if self.consume(&Token::Not) {
            let inner = self.parse_comparison()?;
            return Some(Expr::UnaryNot(Box::new(inner)));
        }

        let mut expr = self.parse_additive()?;

        // At most ONE comparison per expression level. Chained comparisons
        // (`a < b < c`) are an authoring mistake in a security DSL: accepting
        // them would silently compare a boolean result against an integer,
        // producing a wrong verdict instead of an error. Reject by leaving
        // the second operator unconsumed (the trailing-token check in
        // `parse_expression` then fails the parse).
        let op = if self.consume(&Token::EqEq) {
            Some(BinaryOp::Eq)
        } else if self.consume(&Token::NotEq) {
            Some(BinaryOp::Ne)
        } else if self.consume(&Token::Ge) {
            Some(BinaryOp::Ge)
        } else if self.consume(&Token::Le) {
            Some(BinaryOp::Le)
        } else if self.consume(&Token::Gt) {
            Some(BinaryOp::Gt)
        } else if self.consume(&Token::Lt) {
            Some(BinaryOp::Lt)
        } else {
            None
        };

        if let Some(op) = op {
            let right = self.parse_additive()?;
            expr = Expr::Binary {
                left: Box::new(expr),
                op,
                right: Box::new(right),
            };
        }

        Some(expr)
    }

    fn parse_additive(&mut self) -> Option<Expr> {
        let mut expr = self.parse_multiplicative()?;

        loop {
            let op = if self.consume(&Token::Plus) {
                Some(BinaryOp::Add)
            } else if self.consume(&Token::Minus) {
                Some(BinaryOp::Sub)
            } else {
                None
            };

            let Some(op) = op else {
                break;
            };

            let right = self.parse_multiplicative()?;
            expr = Expr::Binary {
                left: Box::new(expr),
                op,
                right: Box::new(right),
            };
        }

        Some(expr)
    }

    fn parse_multiplicative(&mut self) -> Option<Expr> {
        let mut expr = self.parse_unary()?;

        loop {
            let op = if self.consume(&Token::Star) {
                Some(BinaryOp::Mul)
            } else if self.consume(&Token::Slash) {
                Some(BinaryOp::Div)
            } else {
                None
            };

            let Some(op) = op else {
                break;
            };

            let right = self.parse_unary()?;
            expr = Expr::Binary {
                left: Box::new(expr),
                op,
                right: Box::new(right),
            };
        }

        Some(expr)
    }

    fn parse_unary(&mut self) -> Option<Expr> {
        // Unary minus: fold integer literals (`-5` parses as Integer(-5)) and
        // lower any other operand to `0 - operand` so the evaluator needs no
        // new node type.
        if self.consume(&Token::Minus) {
            let operand = self.parse_unary()?;
            return match operand {
                Expr::Integer(value) => Some(Expr::Integer(value.checked_neg()?)),
                other => Some(Expr::Binary {
                    left: Box::new(Expr::Integer(0)),
                    op: BinaryOp::Sub,
                    right: Box::new(other),
                }),
            };
        }
        self.parse_postfix()
    }

    fn parse_postfix(&mut self) -> Option<Expr> {
        let mut expr = self.parse_primary()?;

        loop {
            if self.consume(&Token::Dot) {
                let name = self.expect_identifier()?;
                let args = if self.consume(&Token::LParen) {
                    self.parse_arguments()?
                } else {
                    return None;
                };
                expr = Expr::MethodCall {
                    receiver: Box::new(expr),
                    name,
                    args,
                };
            } else {
                break;
            }
        }

        Some(expr)
    }

    fn parse_primary(&mut self) -> Option<Expr> {
        match self.peek()?.clone() {
            Token::Integer(value) => {
                self.pos += 1;
                Some(Expr::Integer(value))
            }
            Token::String(value) => {
                self.pos += 1;
                Some(Expr::String(value))
            }
            Token::Identifier(name) => {
                self.pos += 1;
                if self.consume(&Token::LParen) {
                    let args = self.parse_arguments()?;
                    Some(Expr::FunctionCall { name, args })
                } else {
                    Some(Expr::Identifier(name))
                }
            }
            Token::LParen => {
                self.pos += 1;
                let expr = self.parse_expression()?;
                if !self.consume(&Token::RParen) {
                    return None;
                }
                Some(expr)
            }
            Token::LBracket => {
                self.pos += 1;
                let mut items = Vec::new();
                if self.consume(&Token::RBracket) {
                    return Some(Expr::List(items));
                }
                loop {
                    items.push(self.parse_expression()?);
                    if self.consume(&Token::Comma) {
                        continue;
                    }
                    if self.consume(&Token::RBracket) {
                        break;
                    }
                    return None;
                }
                Some(Expr::List(items))
            }
            _ => None,
        }
    }

    fn parse_arguments(&mut self) -> Option<Vec<Expr>> {
        let mut args = Vec::new();
        if self.consume(&Token::RParen) {
            return Some(args);
        }

        loop {
            args.push(self.parse_expression()?);
            if self.consume(&Token::Comma) {
                continue;
            }
            if self.consume(&Token::RParen) {
                break;
            }
            return None;
        }

        Some(args)
    }

    fn expect_identifier(&mut self) -> Option<String> {
        match self.peek()?.clone() {
            Token::Identifier(name) => {
                self.pos += 1;
                Some(name)
            }
            _ => None,
        }
    }

    fn consume(&mut self, token: &Token) -> bool {
        if self.peek() == Some(token) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }
}

#[must_use]
#[allow(missing_docs)]
pub fn parse_expression(input: &str) -> Option<Expr> {
    let mut parser = Parser::new(input);
    let ast = parser.parse_expression()?;
    if parser.peek().is_some() {
        return None;
    }
    Some(ast)
}
