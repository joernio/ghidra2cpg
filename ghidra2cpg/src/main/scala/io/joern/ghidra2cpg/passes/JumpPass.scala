package io.joern.ghidra2cpg.passes

import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.EdgeTypes
import io.shiftleft.passes.{CpgPass, DiffGraph}
import io.shiftleft.semanticcpg.language._
class JumpPass(cpg: Cpg) extends CpgPass(cpg) {

  override def run(): Iterator[DiffGraph] = {
    implicit val diffGraph: DiffGraph.Builder = DiffGraph.newBuilder
    cpg.call
      .nameExact("<operator>.goto")
      .where(_.argument.order(1).isLiteral)
      .foreach { sourceCall =>
        val destinationAddress = sourceCall.argument.order(1).code.l.headOption.getOrElse("")
        cpg.call.lineNumber(Integer.parseInt(destinationAddress, 16)).foreach { destination =>
          diffGraph.addEdge(sourceCall, destination, EdgeTypes.CFG)
        }
      }
    Iterator(diffGraph.build())
  }
}
