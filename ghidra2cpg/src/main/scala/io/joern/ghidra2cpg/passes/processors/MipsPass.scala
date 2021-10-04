package io.joern.ghidra2cpg.passes.processors

import ghidra.app.decompiler.DecompInterface
import ghidra.program.flatapi.FlatProgramAPI
import ghidra.program.model.listing.{Function, Instruction, Program}
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.nodes
import io.shiftleft.codepropertygraph.generated.nodes.{NewCall, NewCallBuilder}
import io.shiftleft.passes.IntervalKeyPool
import io.shiftleft.proto.cpg.Cpg.DispatchTypes

import scala.collection.immutable._

class MipsPass(
    cpg: Cpg,
    keyPool: Option[IntervalKeyPool]
) extends FunctionPass(cpg, Some(keyPool.split(1))) {
  def getInstructions: HashMap[String, String] =
    HashMap(
      "_addiu" -> "<operator>.assignment",
      "_li"    -> "<operator>.assignment",
      "_lw"    -> "<operator>.assignment",
      "_nop"   -> "<operator>.NOP",
      "_or"    -> "<operator>.or",
      "_sw"    -> "<operator>.assignment",
      "addiu"  -> "<operator>.assignment",
      "addu"   -> "<operator>.assignment",
      "and"    -> "<operator>.and",
      "b"      -> "<operator>.goto",
      "bal"    -> "CALL",
      "beq"    -> "<operator>.goto",
      "bne"    -> "<operator>.goto",
      "jalr"   -> "CALL",
      "jr"     -> "RETURN",
      "lbu"    -> "<operator>.assignment",
      "li"     -> "<operator>.assignment",
      "lui"    -> "<operator>.assignment",
      "lw"     -> "<operator>.assignment",
      "nop"    -> "<operator>.NOP",
      "or"     -> "<operator>.or",
      "ori"    -> "<operator>.or",
      "sb"     -> "<operator>.assignment",
      "sll"    -> "<operator>.assignment",
      "sltu"   -> "<operator>.assignment",
      "sra"    -> "<operator>.assignment",
      "srl"    -> "<operator>.assignment",
      "subu"   -> "<operator>.assignment",
      "sw"     -> "<operator>.assignment"
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
