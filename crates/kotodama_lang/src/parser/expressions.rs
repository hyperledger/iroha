//! Expression precedence, literals, postfix operations and named call arguments.
//!
//! This owner extends the one CST/AST grammar lowerer: every expression keeps
//! its original source facts, syntax outline, nesting checks and pending-value
//! cleanup. Statement, binding-pattern and type parsing remain with the parent;
//! they enter this grammar through four parent-restricted methods.

use super::*;

struct ParsedCallArguments {
    args: PendingExprs,
    argument_names: Option<Vec<Option<String>>>,
    argument_name_nodes: Vec<Option<NodeId>>,
    ranges: Vec<TextRange>,
}
impl<'a> CstAstLowerer<'a> {
    pub(super) fn parse_expr(&mut self) -> ParseResult<Expr> {
        let start = self.current_start();
        let expression = self.parse_conditional()?;
        let end = self.previous_end(start);
        let range = TextRange::new(start, end);
        if expression
            .source()
            .is_some_and(|source| source.range == range)
        {
            Ok(expression)
        } else {
            Ok(self.source_expression(AstNodeKind::Expression, range, expression))
        }
    }
    pub(super) fn parse_expr_before_block(&mut self) -> ParseResult<Expr> {
        let previous = std::mem::replace(&mut self.allow_struct_literals, false);
        let result = self.parse_expr();
        self.allow_struct_literals = previous;
        result
    }
    pub(super) fn parse_statement_expression_candidate(&mut self) -> ParseResult<Expr> {
        let previous = std::mem::replace(&mut self.allow_statement_if_expression, true);
        let result = self.parse_expr();
        self.allow_statement_if_expression = previous;
        result
    }
    fn parse_conditional(&mut self) -> ParseResult<Expr> {
        enum Frame {
            Then {
                start: u32,
                condition: PendingExpr,
            },
            Else {
                start: u32,
                condition: PendingExpr,
                then_expr: PendingExpr,
            },
        }
        let mut frames = Vec::new();
        let mut current = PendingExpr::new(self.parse_logical_or()?);
        loop {
            if self.peek(TokenKind::Question) && self.question_starts_ternary() {
                let question = self.bump();
                let conditional_depth = self
                    .current_delimiter_depth()
                    .saturating_add(frames.len())
                    .saturating_add(1);
                if conditional_depth > self.max_nesting {
                    return Err(self.nesting_error(question.range));
                }
                let start = current
                    .as_ref()
                    .source()
                    .map_or_else(|| self.current_start(), |source| source.range.start);
                frames.push(Frame::Then {
                    start,
                    condition: current,
                });
                current = PendingExpr::new(self.parse_logical_or()?);
                continue;
            }
            match frames.pop() {
                Some(Frame::Then { start, condition }) => {
                    self.expect(TokenKind::Colon)?;
                    frames.push(Frame::Else {
                        start,
                        condition,
                        then_expr: current,
                    });
                    current = PendingExpr::new(self.parse_logical_or()?);
                }
                Some(Frame::Else {
                    start,
                    mut condition,
                    mut then_expr,
                }) => {
                    let expression = self.source_expression_from(
                        start,
                        Expr::Conditional {
                            cond: Box::new(condition.take()),
                            then_expr: Box::new(then_expr.take()),
                            else_expr: Box::new(current.take()),
                        },
                    );
                    current.replace(expression);
                }
                None => return Ok(current.into_inner()),
            }
        }
    }
    fn parse_logical_or(&mut self) -> ParseResult<Expr> {
        let start = self.current_start();
        let mut expr = PendingExpr::new(self.parse_logical_and()?);
        loop {
            if self.peek(TokenKind::OrOr) {
                self.bump();
                let rhs = self.parse_logical_and()?;
                let expression = self.source_expression_from(
                    start,
                    Expr::Binary {
                        op: BinaryOp::Or,
                        left: Box::new(expr.take()),
                        right: Box::new(rhs),
                    },
                );
                expr.replace(expression);
            } else {
                break;
            }
        }
        Ok(expr.into_inner())
    }
    fn parse_logical_and(&mut self) -> ParseResult<Expr> {
        let start = self.current_start();
        let mut expr = PendingExpr::new(self.parse_comparison()?);
        loop {
            if self.peek(TokenKind::AndAnd) {
                self.bump();
                let rhs = self.parse_comparison()?;
                let expression = self.source_expression_from(
                    start,
                    Expr::Binary {
                        op: BinaryOp::And,
                        left: Box::new(expr.take()),
                        right: Box::new(rhs),
                    },
                );
                expr.replace(expression);
            } else {
                break;
            }
        }
        Ok(expr.into_inner())
    }
    fn parse_comparison(&mut self) -> ParseResult<Expr> {
        let start = self.current_start();
        let mut expr = PendingExpr::new(self.parse_term()?);
        loop {
            let op = if self.peek(TokenKind::EqualEqual) {
                self.bump();
                Some(BinaryOp::Eq)
            } else if self.peek(TokenKind::BangEqual) {
                self.bump();
                Some(BinaryOp::Ne)
            } else if self.peek(TokenKind::LessEqual) {
                self.bump();
                Some(BinaryOp::Le)
            } else if self.peek(TokenKind::Less) {
                self.bump();
                Some(BinaryOp::Lt)
            } else if self.peek(TokenKind::GreaterEqual) {
                self.bump();
                Some(BinaryOp::Ge)
            } else if self.peek(TokenKind::Greater) {
                self.bump();
                Some(BinaryOp::Gt)
            } else {
                None
            };
            if let Some(op) = op {
                let rhs = self.parse_term()?;
                let expression = self.source_expression_from(
                    start,
                    Expr::Binary {
                        op,
                        left: Box::new(expr.take()),
                        right: Box::new(rhs),
                    },
                );
                expr.replace(expression);
            } else {
                break;
            }
        }
        Ok(expr.into_inner())
    }
    pub(super) fn parse_term(&mut self) -> ParseResult<Expr> {
        let start = self.current_start();
        let mut expr = PendingExpr::new(self.parse_factor()?);
        loop {
            let op = if self.peek(TokenKind::Plus) {
                self.bump();
                Some(BinaryOp::Add)
            } else if self.peek(TokenKind::Minus) {
                self.bump();
                Some(BinaryOp::Sub)
            } else {
                None
            };
            if let Some(op) = op {
                let rhs = self.parse_factor()?;
                let expression = self.source_expression_from(
                    start,
                    Expr::Binary {
                        op,
                        left: Box::new(expr.take()),
                        right: Box::new(rhs),
                    },
                );
                expr.replace(expression);
            } else {
                break;
            }
        }
        Ok(expr.into_inner())
    }
    fn parse_factor(&mut self) -> ParseResult<Expr> {
        let start = self.current_start();
        let mut expr = PendingExpr::new(self.parse_unary()?);
        loop {
            let op = if self.peek(TokenKind::Star) {
                self.bump();
                Some(BinaryOp::Mul)
            } else if self.peek(TokenKind::Slash) {
                self.bump();
                Some(BinaryOp::Div)
            } else if self.peek(TokenKind::Percent) {
                self.bump();
                Some(BinaryOp::Mod)
            } else {
                None
            };
            if let Some(op) = op {
                let rhs = self.parse_unary()?;
                let expression = self.source_expression_from(
                    start,
                    Expr::Binary {
                        op,
                        left: Box::new(expr.take()),
                        right: Box::new(rhs),
                    },
                );
                expr.replace(expression);
            } else {
                break;
            }
        }
        Ok(expr.into_inner())
    }
    fn parse_unary(&mut self) -> ParseResult<Expr> {
        let mut prefixes: Vec<(UnaryOp, Token)> = Vec::new();
        loop {
            if self.peek(TokenKind::Minus) {
                let minus = self.bump();
                if let Some(token) = self.tokens.get(self.pos).cloned()
                    && let TokenKind::Number(spelling) = token.kind.clone()
                {
                    self.bump();
                    let value = parse_integer_value(&spelling, true).map_err(|_| {
                        self.coded_error(
                            token.clone(),
                            "E_INT_LITERAL_OVERFLOW",
                            "integer literal is outside the signed Kotodama int domain",
                        )
                    })?;
                    let expr =
                        self.source_expression_from(minus.range.start, bigint_literal_expr(value));
                    let mut expr = self.parse_postfix(expr, minus.range.start)?;
                    for (op, token) in prefixes.into_iter().rev() {
                        expr = self.source_expression_from(
                            token.range.start,
                            Expr::Unary {
                                op,
                                expr: Box::new(expr),
                            },
                        );
                    }
                    return Ok(expr);
                }
                if let Some(token) = self.tokens.get(self.pos).cloned()
                    && let TokenKind::DecimalLiteral(spelling) = token.kind.clone()
                {
                    self.bump();
                    let range = TextRange::new(minus.range.start, token.range.end);
                    let node = self.facts.source_map.allocate_owned(
                        AstNodeKind::DecimalLiteral,
                        range,
                        self.current_function,
                    );
                    let expr = self.sourced_expression(
                        node,
                        SourceRange::new(self.facts.source_map.source(), range),
                        Expr::DecimalLiteral(format!("-{spelling}")),
                    );
                    let mut expr = self.parse_postfix(expr, minus.range.start)?;
                    for (op, token) in prefixes.into_iter().rev() {
                        expr = self.source_expression_from(
                            token.range.start,
                            Expr::Unary {
                                op,
                                expr: Box::new(expr),
                            },
                        );
                    }
                    return Ok(expr);
                }
                prefixes.push((UnaryOp::Neg, minus));
            } else if self.peek(TokenKind::Bang) {
                prefixes.push((UnaryOp::Not, self.bump()));
            } else {
                break;
            }
        }
        let postfix_start = self.current_start();
        let primary = self.parse_primary()?;
        let mut expr = self.parse_postfix(primary, postfix_start)?;
        for (op, token) in prefixes.into_iter().rev() {
            expr = self.source_expression_from(
                token.range.start,
                Expr::Unary {
                    op,
                    expr: Box::new(expr),
                },
            );
        }
        Ok(expr)
    }
    fn parse_postfix(&mut self, expr: Expr, expression_start: u32) -> ParseResult<Expr> {
        let mut expr = PendingExpr::new(expr);
        loop {
            if self.peek(TokenKind::Dot) {
                self.bump();
                // Accept `ident` or numeric tuple index after '.'
                let (field, field_token) = if let Some(token) = self.tokens.get(self.pos).cloned() {
                    match token.kind.clone() {
                        TokenKind::Ident(s) => {
                            self.bump();
                            (s, Some(token))
                        }
                        TokenKind::Number(n) => {
                            self.bump();
                            let index = self.number_to_usize(&token, &n, "tuple index")?;
                            (index.to_string(), None)
                        }
                        _ => {
                            // Avoid borrowing self immutably and mutably in a single expression
                            let tok = self.bump();
                            return Err(
                                self.expected_error(tok, "a field name or tuple index after `.`")
                            );
                        }
                    }
                } else {
                    let tok = self.bump();
                    return Err(self.expected_error(tok, "a field name or tuple index after `.`"));
                };
                // Method-call sugar: `expr.method(args...)` -> `Call { name: method, args: [expr, args...] }`
                if self.peek(TokenKind::LParen) {
                    if let Some(token) = field_token.as_ref()
                        && let Some(message) = removed_method_helper_message(&field)
                    {
                        return Err(self.coded_error(
                            token.clone(),
                            removed_method_helper_code(&field),
                            message,
                        ));
                    }
                    self.bump();
                    let parameter_names = self.call_parameter_names(&field, true);
                    let ParsedCallArguments {
                        args,
                        argument_names,
                        argument_name_nodes,
                        ..
                    } = self.parse_call_arguments(parameter_names.as_deref())?;
                    self.expect(TokenKind::RParen)?;
                    // Prepend the receiver as the first argument
                    let mut full_args = Vec::with_capacity(args.len() + 1);
                    full_args.push(expr.take());
                    let mut parsed_args = args.into_inner();
                    full_args.append(&mut parsed_args);
                    if let Some(token) = field_token.as_ref() {
                        let call_end = self.previous_end(token.range.end);
                        let (node, source) = self.record_call(
                            field.clone(),
                            token.range,
                            TextRange::new(expression_start, call_end),
                            true,
                            argument_name_nodes,
                        );
                        let call_name = match field.as_str() {
                            "get" => STATE_MAP_GET_INTRINSIC.to_owned(),
                            _ => field,
                        };
                        let expression = self.sourced_expression(
                            node,
                            source,
                            Expr::Call {
                                name: call_name,
                                args: full_args,
                                argument_names,
                                implicit_receiver: true,
                            },
                        );
                        expr.replace(expression);
                        continue;
                    }
                    let call_name = match field.as_str() {
                        "get" => STATE_MAP_GET_INTRINSIC.to_owned(),
                        _ => field,
                    };
                    let expression = self.source_expression_from(
                        expression_start,
                        Expr::Call {
                            name: call_name,
                            args: full_args,
                            argument_names,
                            implicit_receiver: true,
                        },
                    );
                    expr.replace(expression);
                } else {
                    let expression = self.source_expression_from(
                        expression_start,
                        Expr::Member {
                            object: Box::new(expr.take()),
                            field,
                        },
                    );
                    expr.replace(expression);
                }
            } else if self.peek(TokenKind::LBracket) {
                self.bump();
                let mut idx = PendingExpr::new(self.parse_expr()?);
                self.expect(TokenKind::RBracket)?;
                let range = TextRange::new(expression_start, self.previous_end(expression_start));
                let node = self.facts.source_map.allocate_owned(
                    AstNodeKind::IndexExpression,
                    range,
                    self.current_function,
                );
                let expression = self.sourced_expression(
                    node,
                    SourceRange::new(self.facts.source_map.source(), range),
                    Expr::Index {
                        target: Box::new(expr.take()),
                        index: Box::new(idx.take()),
                    },
                );
                expr.replace(expression);
            } else if self.peek(TokenKind::Question) && !self.question_starts_ternary() {
                self.bump();
                let expression = self.source_expression_from(
                    expression_start,
                    Expr::Propagate(Box::new(expr.take())),
                );
                expr.replace(expression);
            } else {
                break;
            }
        }
        Ok(expr.into_inner())
    }
    fn parse_primary(&mut self) -> ParseResult<Expr> {
        let tok = self.bump();
        let expression = match &tok.kind {
            TokenKind::True => Expr::Bool(true),
            TokenKind::False => Expr::Bool(false),
            TokenKind::Number(spelling) => {
                bigint_literal_expr(parse_integer_value(spelling, false).map_err(|_| {
                    self.coded_error(
                        tok.clone(),
                        "E_INT_LITERAL_OVERFLOW",
                        "integer literal is outside the signed Kotodama int domain",
                    )
                })?)
            }
            TokenKind::DecimalLiteral(spelling) => {
                let range = tok.range;
                let node = self.facts.source_map.allocate_owned(
                    AstNodeKind::DecimalLiteral,
                    range,
                    self.current_function,
                );
                self.sourced_expression(
                    node,
                    SourceRange::new(self.facts.source_map.source(), range),
                    Expr::DecimalLiteral(spelling.clone()),
                )
            }
            TokenKind::String(s) => Expr::String(s.clone()),
            TokenKind::Bytes(bytes) => Expr::Bytes(bytes.clone()),
            TokenKind::Ident(name) => self.parse_named_primary(tok.clone(), name.clone())?,
            TokenKind::Permission => {
                self.parse_named_primary(tok.clone(), "permission".to_owned())?
            }
            TokenKind::If => {
                self.pos = self.pos.saturating_sub(1);
                let statement_context =
                    std::mem::replace(&mut self.allow_statement_if_expression, false);
                let parsed = self.parse_if_expression(statement_context);
                self.allow_statement_if_expression = statement_context;
                parsed?
            }
            TokenKind::Match => {
                self.pos = self.pos.saturating_sub(1);
                self.parse_match_expression()?
            }
            TokenKind::State if self.peek(TokenKind::ColonColon) => {
                self.parse_named_primary(tok.clone(), "state".to_owned())?
            }
            TokenKind::LParen => self.parse_parenthesized(tok.clone())?,
            TokenKind::LBracket => self.parse_list_expression(tok.clone())?,
            _ => {
                // An absent expression has no single punctuation token to
                // name, but the lossless CST still needs a concrete,
                // zero-width recovery token at the failed primary.  An
                // identifier is the canonical side-effect-free expression
                // placeholder and, unlike deriving recovery from diagnostic
                // prose, keeps editor recovery stable when messages change.
                let mut error = self.expected_error(tok, "an expression").with_help(
                    "a value goes here: a literal, a name, a call, or a parenthesized expression",
                );
                error.expected = Some(SyntaxKind::Ident);
                error.expected_owner = self.syntax.current();
                return Err(error);
            }
        };
        let range = TextRange::new(tok.range.start, self.previous_end(tok.range.end));
        if expression
            .source()
            .is_some_and(|source| source.range == range)
        {
            Ok(expression)
        } else {
            Ok(self.source_expression(AstNodeKind::Expression, range, expression))
        }
    }
    fn parse_list_expression(&mut self, opening: Token) -> ParseResult<Expr> {
        let start = opening.range.start;
        let syntax_list = self.syntax_start(SyntaxKind::ListExpr, start);
        let result = self.parse_list_expression_inner(opening);
        if result
            .as_ref()
            .is_ok_and(|expression| matches!(expression.kind(), Expr::ListComprehension { .. }))
        {
            self.syntax_set_kind(syntax_list, SyntaxKind::ListComprehension);
        }
        self.syntax_finish(syntax_list, start);
        result
    }
    fn parse_list_expression_inner(&mut self, opening: Token) -> ParseResult<Expr> {
        if self.peek(TokenKind::RBracket) {
            self.bump();
            return Ok(Expr::List(Vec::new()));
        }
        let mut first = PendingExpr::new(self.parse_expr()?);
        if self.peek(TokenKind::For) {
            self.bump();
            let owner = self.begin_node(AstNodeKind::ListComprehension, opening.range.start);
            let (item, item_token) = self.expect_ident_token()?;
            self.record_binding(
                owner,
                0,
                item.clone(),
                item_token.range,
                BindingFactKind::Comprehension,
            );
            self.expect(TokenKind::In)?;
            let mut source = PendingExpr::new(self.parse_expr()?);
            let mut condition = if self.peek(TokenKind::If) {
                self.bump();
                Some(PendingExpr::new(self.parse_expr()?))
            } else {
                None
            };
            self.expect(TokenKind::RBracket)?;
            let range = TextRange::new(opening.range.start, self.previous_end(opening.range.end));
            let expression = Expr::ListComprehension {
                expression: Box::new(first.take()),
                item,
                source: Box::new(source.take()),
                condition: condition
                    .as_mut()
                    .map(|condition| Box::new(condition.take())),
            };
            return Ok(self.finish_owned_expression(
                owner,
                AstNodeKind::ListComprehension,
                range,
                expression,
            ));
        }
        let mut elements = PendingExprs::new(vec![first.take()]);
        while self.peek(TokenKind::Comma) {
            self.bump();
            if self.peek(TokenKind::RBracket) {
                break;
            }
            elements.push(self.parse_expr()?);
        }
        self.expect(TokenKind::RBracket)?;
        Ok(Expr::List(elements.into_inner()))
    }
    fn parse_parenthesized(&mut self, opening: Token) -> ParseResult<Expr> {
        let group_start = opening.range.start;
        let mut openings = vec![opening];
        while self.peek(TokenKind::LParen) {
            openings.push(self.bump());
        }
        let opening_count = openings.len();
        let mut represented_parentheses = 0_usize;
        let mut expression = PendingExpr::new(if self.peek(TokenKind::RParen) {
            let opening = openings.pop().expect("unit has an opening parenthesis");
            let closing = self.bump();
            represented_parentheses = 1;
            self.source_expression(
                AstNodeKind::Expression,
                TextRange::new(opening.range.start, closing.range.end),
                Expr::Tuple(Vec::new()),
            )
        } else {
            self.parse_expr()?
        });
        for _ in openings.iter().rev() {
            if self.peek(TokenKind::Comma) {
                let mut elements = PendingExprs::new(vec![expression.take()]);
                while self.peek(TokenKind::Comma) {
                    self.bump();
                    elements.push(self.parse_expr()?);
                }
                expression.replace(Expr::Tuple(elements.into_inner()));
                represented_parentheses = represented_parentheses.saturating_add(1);
            }
            self.expect(TokenKind::RParen)?;
        }
        let range = TextRange::new(group_start, self.previous_end(group_start));
        let expression = if expression
            .as_ref()
            .source()
            .is_some_and(|source| source.range == range)
        {
            expression.take()
        } else {
            self.source_expression(AstNodeKind::Expression, range, expression.take())
        };
        Ok(self.add_expression_syntax_depth(
            expression,
            opening_count.saturating_sub(represented_parentheses),
        ))
    }
    fn parse_named_primary(&mut self, ident_token: Token, mut name: String) -> ParseResult<Expr> {
        // Keyword tokens stay reserved as bindings and declarations. Canonical
        // V1 capability paths that intentionally use branded keywords admit
        // them only after `::`; they never become ordinary identifiers.
        while self.peek(TokenKind::ColonColon) {
            self.bump();
            let segment = self.expect_namespace_segment()?;
            name.push_str("::");
            name.push_str(&segment);
        }
        let name_end = self
            .tokens
            .get(self.pos.saturating_sub(1))
            .map_or(ident_token.range.end, |token| token.range.end);
        let name_range = TextRange::new(ident_token.range.start, name_end);
        if name == "json" {
            // Like struct literals, a `json { ... }` object is not recognised
            // directly before a block (`for x in json { ... }` iterates a local
            // named `json`); parenthesize it there.
            if self.allow_struct_literals && self.peek(TokenKind::LBrace) {
                return self.parse_json_object(ident_token.range.start);
            }
            if self.peek(TokenKind::LBracket) {
                return self.parse_json_array(ident_token.range.start);
            }
        }
        if self.peek(TokenKind::Bang) {
            return Err(self
                .coded_error(
                    ident_token,
                    "K1001",
                    format!("`{name}!` looks like a macro call; Kotodama has no macros"),
                )
                .with_help("use an ordinary typed constructor such as `AccountId::parse(\"...\")`, `Json::parse(\"{...}\")`, or a `b\"...\"` bytes literal"));
        }
        if let Some(error) = self.foreign_sum_constructor_error(&ident_token, &name, name_range) {
            return Err(error);
        }
        if matches!(
            name.as_str(),
            "option::some" | "option::none" | "result::ok" | "result::err"
        ) && self.peek(TokenKind::LParen)
        {
            self.bump();
            let parameter_names = self.call_parameter_names(&name, false);
            let parsed = self.parse_call_arguments(parameter_names.as_deref())?;
            self.expect(TokenKind::RParen)?;
            let end = self
                .tokens
                .get(self.pos.saturating_sub(1))
                .map_or(ident_token.range.end, |token| token.range.end);
            let range = TextRange::new(ident_token.range.start, end);
            let replacement = self.legacy_sum_replacement(&name, &parsed);
            let canonical = name
                .split_once("::")
                .and_then(|(namespace, variant)| super::canonical_sum_path(namespace, variant))
                .unwrap_or("Option::some");
            let mut error = self
                .coded_error(
                    ident_token,
                    "E_LEGACY_SUM_CONSTRUCTOR",
                    format!("`{name}(...)` is spelled `{canonical}` in Kotodama"),
                )
                .with_help(super::sum_constructor_help());
            error.range = range;
            if let Some(replacement) = replacement {
                error = error.with_fix(range, replacement);
            }
            return Err(error);
        }
        if name == "Option::none" {
            if self.peek(TokenKind::LParen) {
                let opening = self.bump();
                let parameter_names = self.call_parameter_names(&name, false);
                let parsed = self.parse_call_arguments(parameter_names.as_deref())?;
                self.expect(TokenKind::RParen)?;
                let end = self
                    .tokens
                    .get(self.pos.saturating_sub(1))
                    .map_or(opening.range.end, |token| token.range.end);
                let mut error = self
                    .coded_error(
                        opening,
                        "E_SUM_CONSTRUCTOR_FORM",
                        "`Option::none` is a value, not a call; remove the parentheses",
                    )
                    .with_help("the absent value is written `Option::none`; its type comes from the context");
                let written = TextRange::new(ident_token.range.start, end);
                error.range = written;
                if parsed.argument_names.is_none() {
                    error = error.with_fix(written, "Option::none");
                }
                return Err(error);
            }
            return Ok(Expr::OptionNone);
        }
        if matches!(name.as_str(), "Option::some" | "Result::ok" | "Result::err") {
            if !self.peek(TokenKind::LParen) {
                return Err(self
                    .coded_error(
                        ident_token,
                        "E_SUM_CONSTRUCTOR_FORM",
                        format!("`{name}` is called with exactly one payload, for example `{name}(value)`"),
                    )
                    .with_help(super::sum_constructor_help()));
            }
            self.bump();
            let parameter_names = self.call_parameter_names(&name, false);
            let ParsedCallArguments {
                mut args,
                argument_names,
                ..
            } = self.parse_call_arguments(parameter_names.as_deref())?;
            self.expect(TokenKind::RParen)?;
            if argument_names.is_some() || args.len() != 1 {
                let error = self.coded_error(
                    ident_token,
                    "E_SUM_CONSTRUCTOR_ARITY",
                    format!("`{name}` expects exactly one positional active payload"),
                );
                return Err(error);
            }
            let payload = Box::new(args.pop().expect("one constructor argument"));
            return Ok(match name.as_str() {
                "Option::some" => Expr::OptionSome(payload),
                "Result::ok" => Expr::ResultOk(payload),
                "Result::err" => Expr::ResultErr(payload),
                _ => unreachable!("matched canonical constructor"),
            });
        }
        if self.allow_struct_literals && self.peek(TokenKind::LBrace) {
            let start = ident_token.range.start;
            let syntax_literal = self.syntax_start(SyntaxKind::StructLiteral, start);
            self.bump();
            let result = (|| -> ParseResult<Expr> {
                let fields = self.parse_struct_literal_fields()?;
                self.expect(TokenKind::RBrace)?;
                Ok(Expr::StructLiteral {
                    name,
                    fields: fields.into_inner(),
                })
            })();
            self.syntax_finish(syntax_literal, start);
            result
        } else if self.peek(TokenKind::LParen) {
            if name.contains("::")
                && let Some(message) = removed_free_helper_message(&name)
            {
                let mut error =
                    self.coded_error(ident_token, removed_free_helper_code(&name), message);
                if let Some(replacement) = retired_trigger_alias_replacement(&name) {
                    error.range = name_range;
                    error = error.with_fix(name_range, replacement);
                }
                return Err(error);
            }
            self.bump();
            let parameter_names = self.call_parameter_names(&name, false);
            let ParsedCallArguments {
                args,
                argument_names,
                argument_name_nodes,
                ..
            } = self.parse_call_arguments(parameter_names.as_deref())?;
            self.expect(TokenKind::RParen)?;
            let call_end = self.previous_end(name_range.end);
            let (node, source) = self.record_call(
                name.clone(),
                name_range,
                TextRange::new(ident_token.range.start, call_end),
                false,
                argument_name_nodes,
            );
            Ok(self.sourced_expression(
                node,
                source,
                Expr::Call {
                    name,
                    args: args.into_inner(),
                    argument_names,
                    implicit_receiver: false,
                },
            ))
        } else {
            Ok(Expr::Ident(name))
        }
    }
    /// `E_LEGACY_SUM_CONSTRUCTOR` for `Some(x)`, `None`, `Ok(x)`, `Err(x)` and
    /// mis-cased paths such as `Option::Some(x)`, with an exact fix.
    ///
    /// The lowercase `option::`/`result::` call form keeps its own payload-
    /// aware fix below; bare lowercase names are ordinary identifiers.
    fn foreign_sum_constructor_error(
        &self,
        token: &Token,
        name: &str,
        name_range: TextRange,
    ) -> Option<Box<ParseError>> {
        let calls = self.peek(TokenKind::LParen);
        let canonical = match name.split_once("::") {
            Some((namespace, variant)) => {
                let canonical = super::canonical_sum_path(namespace, variant)?;
                if canonical == name
                    || (name.starts_with("option::") || name.starts_with("result::")) && calls
                {
                    return None;
                }
                canonical
            }
            None => {
                let canonical = super::foreign_sum_constructor(name)?;
                if name == "None" && calls {
                    // `None()`: the absent value is not a call. An empty
                    // argument list is rewritten together with the name.
                    let mut error = self
                        .coded_error(
                            token.clone(),
                            "E_LEGACY_SUM_CONSTRUCTOR",
                            "`None` is spelled `Option::none` in Kotodama, and it is a value, not a call",
                        )
                        .reported_at(name_range)
                        .with_help(super::sum_constructor_help());
                    if self.peek_n(1, TokenKind::RParen)
                        && let Some(closing) = self.tokens.get(self.pos + 1)
                    {
                        error = error.with_fix(
                            TextRange::new(name_range.start, closing.range.end),
                            canonical,
                        );
                    }
                    return Some(error);
                }
                // `Some`/`Ok`/`Err` are constructor calls; a bare name is an
                // ordinary identifier.
                if name != "None" && !calls {
                    return None;
                }
                canonical
            }
        };
        Some(
            self.coded_error(
                token.clone(),
                "E_LEGACY_SUM_CONSTRUCTOR",
                format!("`{name}` is spelled `{canonical}` in Kotodama"),
            )
            .reported_at(name_range)
            .with_help(super::sum_constructor_help())
            .with_fix(name_range, canonical),
        )
    }
    fn parse_json_object(&mut self, start: u32) -> ParseResult<Expr> {
        self.with_syntax(
            SyntaxKind::JsonObjectExpr,
            start,
            Self::parse_json_object_inner,
        )
    }
    fn parse_json_object_inner(&mut self) -> ParseResult<Expr> {
        self.expect(TokenKind::LBrace)?;
        let mut entries = PendingValues::new(|entry: crate::ast::JsonObjectEntry| {
            crate::ast::drop_expression_iterative(entry.value);
        });
        while !self.peek(TokenKind::RBrace) && !self.peek(TokenKind::EOF) {
            let entry_start = self.current_start();
            let entry = self.with_syntax(SyntaxKind::JsonObjectEntry, entry_start, |this| {
                let key_token = this.bump();
                let key = match &key_token.kind {
                    TokenKind::Ident(key) | TokenKind::String(key) => key.clone(),
                    _ => {
                        return Err(this.expected_error(
                            key_token,
                            "a JSON object key (identifier or string literal)",
                        ));
                    }
                };
                let key_spelling = this
                    .source
                    .get(key_token.range.start as usize..key_token.range.end as usize)
                    .unwrap_or_default()
                    .to_owned();
                this.expect(TokenKind::Colon)?;
                let value = this.parse_expr()?;
                Ok(crate::ast::JsonObjectEntry {
                    key,
                    key_spelling,
                    key_range: key_token.range,
                    value,
                })
            })?;
            entries.push(entry);
            if !self.peek(TokenKind::Comma) {
                break;
            }
            self.bump();
        }
        self.expect(TokenKind::RBrace)?;
        Ok(Expr::JsonObject(entries.into_inner()))
    }
    fn parse_json_array(&mut self, start: u32) -> ParseResult<Expr> {
        self.with_syntax(
            SyntaxKind::JsonArrayExpr,
            start,
            Self::parse_json_array_inner,
        )
    }
    fn parse_json_array_inner(&mut self) -> ParseResult<Expr> {
        self.expect(TokenKind::LBracket)?;
        let mut elements = PendingExprs::new(Vec::new());
        while !self.peek(TokenKind::RBracket) && !self.peek(TokenKind::EOF) {
            elements.push(self.parse_expr()?);
            if !self.peek(TokenKind::Comma) {
                break;
            }
            self.bump();
        }
        self.expect(TokenKind::RBracket)?;
        Ok(Expr::JsonArray(elements.into_inner()))
    }
    fn call_parameter_names(&self, name: &str, implicit_receiver: bool) -> Option<Vec<String>> {
        if !implicit_receiver {
            if let Some(parameters) = self.declared_function_parameters.get(name) {
                return parameters.clone();
            }
            if let Some(builtin) = kotodama_surface::builtins::Builtin::from_source_name(name) {
                return Some(
                    builtin
                        .signature()
                        .parameter_names
                        .iter()
                        .map(|name| (*name).to_owned())
                        .collect(),
                );
            }
        }
        let parameters: &[&str] = match name {
            "Option::some"
            | "option::some"
            | "decimal::from_int"
            | "decimal::to_int_exact"
            | "decimal::to_int_trunc"
            | "quantity::try_from_int"
            | "quantity::try_from_decimal"
            | "decimal::from_quantity"
            | "try_push"
            | "contains" => &["value"],
            "Result::ok" | "result::ok" => &["value"],
            "Result::err" | "result::err" => &["error"],
            "get" => &["index"],
            "try_set" => &["index", "value"],
            "take" => &["limit"],
            "div_round" => &["divisor", "scale", "mode"],
            "ratio_round" => &["divisor", "scale", "mode"],
            "decimal::to_int_round" => &["value", "mode"],
            "get_bool" | "get_int" | "get_decimal" | "get_quantity" | "get_string"
            | "get_bytes" | "get_json" => &["key"],
            _ => return None,
        };
        Some(parameters.iter().map(|name| (*name).to_owned()).collect())
    }
    fn parse_call_arguments(
        &mut self,
        parameter_names: Option<&[String]>,
    ) -> ParseResult<ParsedCallArguments> {
        let start = self
            .tokens
            .get(self.pos.saturating_sub(1))
            .map_or_else(|| self.current_start(), |token| token.range.start);
        let syntax_arguments = self.syntax_start(SyntaxKind::ArgumentList, start);
        let result = self.parse_call_arguments_inner(parameter_names);
        let end = self
            .tokens
            .get(self.pos)
            .filter(|token| matches!(token.kind, TokenKind::RParen))
            .map_or_else(|| self.previous_end(start), |token| token.range.end);
        self.syntax_finish_at(syntax_arguments, end);
        result
    }
    fn parse_call_arguments_inner(
        &mut self,
        _parameter_names: Option<&[String]>,
    ) -> ParseResult<ParsedCallArguments> {
        let mut args = PendingExprs::new(Vec::new());
        let mut names: Vec<Option<String>> = Vec::new();
        let mut argument_name_nodes = Vec::new();
        let mut ranges = Vec::new();
        let mut named_seen = false;
        while !self.peek(TokenKind::RParen) {
            let is_named = self.tokens.get(self.pos).is_some_and(|token| {
                matches!(token.kind, TokenKind::Ident(_))
                    || crate::lexer::v1_keyword_spelling(&token.kind).is_some()
            }) && self.peek_n(1, TokenKind::Colon);
            if named_seen && !is_named {
                let token = self.tokens[self.pos].clone();
                return Err(self.coded_error(
                    token,
                    "E_POSITIONAL_ARGUMENT_ORDER",
                    "positional arguments must precede named arguments",
                ));
            }
            named_seen |= is_named;
            let argument_start = self.current_start();
            let syntax_named =
                is_named.then(|| self.syntax_start(SyntaxKind::NamedArgument, argument_start));
            let name_node = is_named.then(|| {
                self.facts.source_map.allocate_owned(
                    AstNodeKind::Name,
                    self.tokens[self.pos].range,
                    self.current_function,
                )
            });
            let parsed_argument = (|| -> ParseResult<(Option<String>, Expr)> {
                let name = if is_named {
                    let token = self.bump();
                    let name = match token.kind.clone() {
                        TokenKind::Ident(name) => name,
                        keyword => crate::lexer::v1_keyword_spelling(&keyword)
                            .expect("named argument lookahead requires an identifier or keyword")
                            .to_owned(),
                    };
                    if names.iter().flatten().any(|existing| existing == &name) {
                        return Err(self.coded_error(
                            token,
                            "E_DUPLICATE_NAMED_ARGUMENT",
                            format!("named argument `{name}` is supplied more than once"),
                        ));
                    }
                    self.expect(TokenKind::Colon)?;
                    Some(name)
                } else {
                    None
                };
                let expression = if self.peek(TokenKind::LBrace) {
                    let start = self.current_start();
                    let syntax_record = self.syntax_start(SyntaxKind::ArgumentRecord, start);
                    self.bump();
                    let fields = self.parse_struct_literal_fields()?;
                    self.expect(TokenKind::RBrace)?;
                    self.syntax_finish(syntax_record, start);
                    let range = TextRange::new(start, self.previous_end(start));
                    self.source_expression(
                        AstNodeKind::Expression,
                        range,
                        Expr::ArgumentRecord {
                            fields: fields.into_inner(),
                        },
                    )
                } else {
                    self.parse_expr()?
                };
                Ok((name, expression))
            })();
            if let Some(syntax_named) = syntax_named {
                self.syntax_finish(syntax_named, argument_start);
            }
            let (name, argument) = parsed_argument?;
            names.push(name);
            argument_name_nodes.push(name_node);
            args.push(argument);
            ranges.push(TextRange::new(
                argument_start,
                self.previous_end(argument_start),
            ));
            if !self.peek(TokenKind::Comma) {
                break;
            }
            self.bump();
        }
        Ok(ParsedCallArguments {
            args,
            argument_names: named_seen.then_some(names),
            argument_name_nodes,
            ranges,
        })
    }
    fn legacy_sum_replacement(&self, name: &str, parsed: &ParsedCallArguments) -> Option<String> {
        if parsed.argument_names.is_some() {
            return None;
        }
        let source_argument = |index: usize| {
            let range = parsed.ranges.get(index)?;
            self.source
                .get(range.start as usize..range.end as usize)
                .map(str::trim)
                .filter(|text| !text.contains("//") && !text.contains("/*"))
        };
        match name {
            "option::some" if parsed.args.len() == 1 => {
                Some(format!("Option::some({})", source_argument(0)?))
            }
            "option::none" if parsed.args.len() == 1 => Some("Option::none".into()),
            "result::ok" if parsed.args.len() == 2 => {
                Some(format!("Result::ok({})", source_argument(0)?))
            }
            "result::err" if parsed.args.len() == 2 => {
                Some(format!("Result::err({})", source_argument(1)?))
            }
            _ => None,
        }
    }
    fn parse_struct_literal_fields(&mut self) -> ParseResult<PendingValues<StructLiteralField>> {
        let mut fields = PendingValues::new(|field: StructLiteralField| {
            crate::ast::drop_expression_iterative(field.value);
        });
        while !self.peek(TokenKind::RBrace) {
            let field_start = self.current_start();
            let field = self.with_syntax(SyntaxKind::StructLiteralField, field_start, |this| {
                let token = this.bump();
                let TokenKind::Ident(name) = token.kind.clone() else {
                    return Err(this
                        .expected_error(token, "a struct field name")
                        .with_help("struct literals name every field: `Point { x: 1, y: 2 }`"));
                };
                if fields.iter().any(|field| field.name == name) {
                    return Err(this.coded_error(
                        token,
                        "E_DUPLICATE_STRUCT_FIELD",
                        format!("struct field `{name}` is supplied more than once"),
                    ));
                }
                let (value, shorthand) = if this.peek(TokenKind::Colon) {
                    this.bump();
                    (this.parse_expr()?, false)
                } else {
                    (
                        this.source_expression(
                            AstNodeKind::Expression,
                            token.range,
                            Expr::Ident(name.clone()),
                        ),
                        true,
                    )
                };
                Ok(StructLiteralField {
                    name,
                    value,
                    shorthand,
                })
            })?;
            fields.push(field);
            if !self.peek(TokenKind::Comma) {
                break;
            }
            self.bump();
            if self.peek(TokenKind::RBrace) {
                break;
            }
        }
        Ok(fields)
    }
}
