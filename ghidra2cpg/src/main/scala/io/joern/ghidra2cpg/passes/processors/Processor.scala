package io.joern.ghidra2cpg.passes.processors

import ghidra.program.model.listing.{CodeUnitFormat, CodeUnitFormatOptions, Instruction}
import io.shiftleft.codepropertygraph.generated.nodes.NewCall

import scala.collection.immutable._

abstract class Processor {

  // needed by ghidra for decompiling reasons
  val codeUnitFormat: CodeUnitFormat = new CodeUnitFormat(
    new CodeUnitFormatOptions(
      CodeUnitFormatOptions.ShowBlockName.NEVER,
      CodeUnitFormatOptions.ShowNamespace.NEVER,
      "",
      true,
      true,
      true,
      true,
      true,
      true,
      true
    )
  )
  def getInstructions: HashMap[String, String]
  def addCallNode(instruction: Instruction): NewCall
  def sanitizeMethodName(methodName: String): String = {
    methodName.split(">").lastOption.getOrElse(methodName).replace("[", "").replace("]", "")
  }
}