package io.joern.ghidra2cpg.passes.processors

import ghidra.program.model.listing.Instruction
import io.shiftleft.codepropertygraph.generated.nodes
import io.shiftleft.codepropertygraph.generated.nodes.{NewCall, NewCallBuilder}
import io.shiftleft.proto.cpg.Cpg.DispatchTypes

import io.shiftleft.semanticcpg.language._
import scala.collection.immutable._
import scala.language.implicitConversions


class X86 extends Processor {
  override def getInstructions: HashMap[String, String] =
    HashMap(
      "ADD"       -> "<operator>.incBy",
      "ADDSD"     -> "<operator>.incBy",
      "ADDSS"     -> "<operator>.incBy",
      "AND"       -> "<operator>.assignmentAnd",
      "CALL"      -> "CALL",
      "CMOVA"     -> "<operator>.assignment",
      "CMOVBE"    -> "<operator>.assignment",
      "CMOVC"     -> "<operator>.assignment",
      "CMOVG"     -> "<operator>.assignment",
      "CMOVGE"    -> "<operator>.assignment",
      "CMOVL"     -> "<operator>.assignment",
      "CMOVLE"    -> "<operator>.assignment",
      "CMOVNC"    -> "<operator>.assignment",
      "CMOVNS"    -> "<operator>.assignment",
      "CMOVNZ"    -> "<operator>.assignment",
      "CMOVP"     -> "<operator>.assignment",
      "CMOVS"     -> "<operator>.assignment",
      "CMOVZ"     -> "<operator>.assignment",
      "CMP"       -> "<operator>.compare",
      "DEC"       -> "<operator>.NOP",
      "DIV"       -> "<operator>.division",
      "DIVSD"     -> "<operator>.division",
      "DIVSS"     -> "<operator>.division",
      "ENDBR64"   -> "<operator>.NOP",
      "FADD"      -> "<operator>.incBy",
      "FDIV"      -> "<operator>.division",
      "FDIVP"     -> "<operator>.division",
      "FDIVRP"    -> "<operator>.division",
      "FMULP"     -> "<operator>.multiplication",
      "IDIV"      -> "<operator>.division",
      "IMUL"      -> "<operator>.multiplication",
      "INC"       -> "<operator>.NOP",
      "JA"        -> "<operator>.goto",
      "JB"        -> "<operator>.goto",
      "JBE"       -> "<operator>.goto",
      "JC"        -> "<operator>.goto",
      "JG"        -> "<operator>.goto",
      "JGE"       -> "<operator>.goto",
      "JL"        -> "<operator>.goto",
      "JLE"       -> "<operator>.goto",
      "JMP"       -> "<operator>.goto",
      "JNC"       -> "<operator>.goto",
      "JNO"       -> "<operator>.goto",
      "JNP"       -> "<operator>.goto",
      "JNS"       -> "<operator>.goto",
      "JNZ"       -> "<operator>.goto",
      "JO"        -> "<operator>.goto",
      "JP"        -> "<operator>.goto",
      "JS"        -> "<operator>.goto",
      "JZ"        -> "<operator>.goto",
      "LEA"       -> "<operator>.addressOf",
      "LEAVE"     -> "RETURN",
      "MOV"       -> "<operator>.assignment",
      "MOVAPD"    -> "<operator>.assignment",
      "MOVAPS"    -> "<operator>.assignment",
      "MOVD"      -> "<operator>.assignment",
      "MOVDQA"    -> "<operator>.assignment",
      "MOVDQU"    -> "<operator>.assignment",
      "MOVMSKPD"  -> "<operator>.assignment",
      "MOVQ"      -> "<operator>.assignment",
      "MOVSB.REP" -> "<operator>.assignment",
      "MOVSD"     -> "<operator>.assignment",
      "MOVSQ.REP" -> "<operator>.assignment",
      "MOVSS"     -> "<operator>.assignment",
      "MOVSX"     -> "<operator>.assignment",
      "MOVSXD"    -> "<operator>.assignment",
      "MOVUPS"    -> "<operator>.assignment",
      "MOVZX"     -> "<operator>.assignment",
      "MUL"       -> "<operator>.multiplication",
      "MULSD"     -> "<operator>.multiplication",
      "MULSS"     -> "<operator>.multiplication",
      "NEG"       -> "<operator>.negation",
      "NOP"       -> "<operator>.NOP",
      "NOT"       -> "<operator>.not",
      "OR"        -> "<operator>.or",
      "POP"       -> "<operator>.assignment",
      "PUSH"      -> "<operator>.assignment",
      "PXOR"      -> "<operator>.assignmentXor",
      "RET"       -> "RETURN",
      "ROL"       -> "<operator>.rotateLeft",
      "ROR"       -> "<operator>.rotateRight",
      "SAR"       -> "<operator>.arithmeticShiftRight",
      "SHL"       -> "<operator>.logicalShiftLeft",
      "SHR"       -> "<operator>.logicalShiftRight",
      "SUB"       -> "<operator>.subtraction",
      "SUBSD"     -> "<operator>.subtraction",
      "SUBSS"     -> "<operator>.subtraction",
      "TEST"      -> "<operator>.compare",
      "XADD"      -> "<operator>.incBy",
      "XOR"       -> "<operator>.assignmentXor"
    )
  def addCallNode(instruction: Instruction): NewCall = {
    val node: NewCallBuilder = nodes.NewCall()
    var code: String         = ""
    val mnemonicName =
      getInstructions
        .getOrElse(instruction.getMnemonicString, "UNKNOWN") match {
        case "LEAVE" | "RET" =>
          code = "RET"
          "RET"
        case "CALL" =>
          val operandRepresentationString = sanitizeMethodName(
            codeUnitFormat.getOperandRepresentationString(instruction, 0)
          )
          code = operandRepresentationString
          operandRepresentationString
        case "UNKNOWN" =>
          code = instruction.toString
          "UNKNOWN"
        case operator =>
          code = instruction.toString
          operator
      }

    node
      .name(mnemonicName)
      .code(code)
      .order(0)
      .methodFullName(mnemonicName)
      .dispatchType(DispatchTypes.STATIC_DISPATCH.name())
      .lineNumber(instruction.getMinAddress.getOffsetAsBigInteger.intValue)
      .build
  }
}