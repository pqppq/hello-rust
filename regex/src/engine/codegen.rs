use super::{parser::AST, Instruction};
use crate::helper::safe_add;
use std::{
    error::Error,
    fmt::{self, Display},
};

/// codegen error
#[derive(Debug)]
pub enum CodeGenError {
    PCOverFlow,
    FailStar,
    FailOr,
    FailQuestion,
}

impl Display for CodeGenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CodeGenError: {:?}", self)
    }
}

impl Error for CodeGenError {}

#[derive(Default, Debug)]
struct Generator {
    pc: usize,               // program counter
    insts: Vec<Instruction>, // instructions
}

pub fn get_code(ast: &AST) -> Result<Vec<Instruction>, CodeGenError> {
    let mut generator = Generator::default();
    generator.gen_code(ast)?;
    Ok(generator.insts)
}

/// code generator
impl Generator {
    /// increment program counter
    fn inc_pc(&mut self) -> Result<(), CodeGenError> {
        safe_add(&mut self.pc, &1, || CodeGenError::PCOverFlow)
    }

    /// generate Instructions
    fn gen_seq(&mut self, exprs: &[AST]) -> Result<(), CodeGenError> {
        for e in exprs {
            self.gen_expr(e)?;
        }

        Ok(())
    }

    /// entry point
    fn gen_code(&mut self, ast: &AST) -> Result<(), CodeGenError> {
        self.gen_expr(ast)?;
        self.inc_pc()?;
        self.insts.push(Instruction::Match);
        Ok(())
    }

    fn gen_expr(&mut self, ast: &AST) -> Result<(), CodeGenError> {
        match ast {
            AST::Char(c) => self.gen_char(*c)?,
            AST::Or(e1, e2) => self.gen_or(e1, e2)?,
            AST::Plus(e) => self.gen_plus(e)?,
            AST::Star(e1) => match &**e1 {
                AST::Star(e2) => self.gen_expr(&e2)?,
                AST::Seq(e2) if e2.len() == 1 => {
                    if let Some(e3 @ AST::Star(_)) = e2.get(0) {
                        self.gen_expr(e3)?
                    } else {
                        self.gen_star(e1)?
                    }
                }
                e => self.gen_star(&e)?,
            },
            AST::Question(e) => self.gen_question(e)?,
            AST::Seq(v) => self.gen_seq(v)?,
        }

        Ok(())
    }

    /// generate instruction from Char
    fn gen_char(&mut self, c: char) -> Result<(), CodeGenError> {
        let insts = Instruction::Char(c);
        self.insts.push(insts);
        self.inc_pc()?;
        Ok(())
    }

    ///
    /// generate instruction from Or
    /// ```text
    ///     split L1, L2
    /// L1: e1 code
    ///     jump L3
    /// L2: e2 code
    /// L3:
    /// ```
    fn gen_or(&mut self, e1: &AST, e2: &AST) -> Result<(), CodeGenError> {
        // split L1, L2
        let split_addr = self.pc;
        self.inc_pc()?;
        let split = Instruction::Split(self.pc, 0); // tempolary set L2 to 0
        self.insts.push(split);

        // L1: e1 code
        self.gen_expr(e1)?; // inc pc and push self.insts

        // jmp L3
        let jump_addr = self.pc;
        self.insts.push(Instruction::Jump(0));

        // set L2
        self.inc_pc()?;
        if let Some(Instruction::Split(_, l2)) = self.insts.get_mut(split_addr) {
            *l2 = self.pc;
        } else {
            return Err(CodeGenError::FailOr);
        }

        // L2: e2 code
        self.gen_expr(e2)?;

        // set L3
        if let Some(Instruction::Jump(l3)) = self.insts.get_mut(jump_addr) {
            *l3 = self.pc;
        } else {
            return Err(CodeGenError::FailOr)
        }

        Ok(())
    }

    /// generate instruction from Question
    /// ```text
    ///     split L1, L2
    /// L1: e code
    /// L2:
    /// ```
    fn gen_question(&mut self, e: &AST) -> Result<(), CodeGenError> {
        // split L1, L2
        let split_addr = self.pc;
        self.inc_pc()?;
        let split = Instruction::Split(self.pc, 0); // temporary set L2 to 0
        self.insts.push(split);

        // L1: e code
        self.gen_expr(e)?;

        // set L2
        if let Some(Instruction::Split(_, l2)) = self.insts.get_mut(split_addr) {
            *l2 = self.pc;
            Ok(())
        } else {
            Err(CodeGenError::FailQuestion)
        }
    }

    ///
    /// generate instruction from Plus
    /// ```text
    /// L1: e code
    ///     split L1, L2
    /// L2:
    /// ```
    fn gen_plus(&mut self, e: &AST) -> Result<(), CodeGenError> {
        let l1 = self.pc;
        self.gen_expr(e)?;

        // split L1, L2
        self.inc_pc()?;
        let split = Instruction::Split(l1, self.pc);
        self.insts.push(split);

        Ok(())
    }

    ///
    /// generate instruction from Star
    /// ```text
    /// L1: split L2, L3
    /// L2: e code
    ///     jump L1
    /// L3:
    /// ```
    fn gen_star(&mut self, e: &AST) -> Result<(), CodeGenError> {
        // L1: split L2, L3
        let l1 = self.pc;
        self.inc_pc()?;
        let split = Instruction::Split(self.pc, 0); // temporary set L3 to 0
        self.insts.push(split);

        // L2: e code
        self.gen_expr(e)?;

        // jump L1
        self.inc_pc()?;
        self.insts.push(Instruction::Jump(l1));

        // set L3
        if let Some(Instruction::Split(_, l3)) = self.insts.get_mut(l1) {
            *l3 = self.pc;
            Ok(())
        } else {
            Err(CodeGenError::FailStar)
        }
    }
}
