package io.joern.ghidra2cpg.passes

import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.EdgeTypes
import io.shiftleft.codepropertygraph.generated.nodes.Method
import io.shiftleft.passes.{ConcurrentWriterCpgPass, DiffGraph}
import io.shiftleft.semanticcpg.language._

class JumpPass(cpg: Cpg) extends ConcurrentWriterCpgPass[Method](cpg) {

  override def generateParts(): Array[Method] = cpg.method.toArray

  override def runOnPart(diffGraph: DiffGraph.Builder, method: Method): Unit = {
    implicit val diffGraph: DiffGraph.Builder = DiffGraph.newBuilder
    method.call
      .nameExact("<operator>.goto")
      .where(_.argument.order(1).isLiteral)
      .foreach { sourceCall =>
        sourceCall.argument.order(1).code.l.headOption match {
          case Some(destinationAddress) =>
            method.call.lineNumber(Integer.parseInt(destinationAddress, 16)).foreach {
              destination =>
                diffGraph.addEdge(sourceCall, destination, EdgeTypes.CFG)
            }
          case _ => // Ignore for now
          /*
            TODO:
              - Ask ghidra to resolve addresses of JMPs
           */
        }
      }
  }
}
