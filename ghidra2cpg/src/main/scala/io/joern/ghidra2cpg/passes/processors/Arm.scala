package io.joern.ghidra2cpg.passes.processors

import ghidra.program.model.listing.Instruction
import io.shiftleft.codepropertygraph.generated.nodes
import io.shiftleft.codepropertygraph.generated.nodes.{NewCall, NewCallBuilder}
import io.shiftleft.proto.cpg.Cpg.DispatchTypes

import scala.collection.immutable._

class Arm extends Processor {
  override def getInstructions: HashMap[String, String] =
    HashMap(
      "add"  -> "<operator>.incBy",
      "adrp" -> "TODO",
      "asr"  -> "TODO",
      "b"    -> "<operator>.goto",
      "b.eq" -> "<operator>.goto",
      "b.ne" -> "<operator>.goto",
      "bl"   -> "CALL",
      "blr"  -> "<operator>.goto",
      "br"   -> "<operator>.goto",
      "bti"  -> "<operator>.goto",
      "cbnz" -> "<operator>.goto",
      "cbz"  -> "<operator>.goto",
      "cmp"  -> "<operator>.compare",
      "ldp"  -> "<operator>.addressOf",
      "ldr"  -> "<operator>.addressOf",
      "ldrb" -> "<operator>.addressOf",
      "lsl"  -> "<operator>.addressOf",
      "lsr"  -> "<operator>.addressOf",
      "mov"  -> "<operator>.assignment",
      "movk" -> "<operator>.assignment",
      "nop"  -> "<operator>.NOP",
      "ret"  -> "RETURN",
      "stp"  -> "<operator>.assignment",
      "str"  -> "<operator>.addition",
      "strb" -> "<operator>.assignment",
      "sub"  -> "<operator>.subtraction"
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
