package io.joern.ghidra2cpg.passes

import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.EdgeTypes
import io.shiftleft.codepropertygraph.generated.nodes.{Call, Method}
import io.shiftleft.passes.{DiffGraph, IntervalKeyPool, ParallelCpgPass}
import io.shiftleft.semanticcpg.language._

import scala.util.Try

class JumpPass(cpg: Cpg, keyPool: IntervalKeyPool)
    extends ParallelCpgPass[Method](
      cpg,
      keyPools = Some(keyPool.split(1))
    ) {

  override def partIterator: Iterator[Method] = cpg.method.l.iterator

  private def parseAddress(address: String): Option[Int] = {
    println(s"Attempting to parse address $address")
    Try(Integer.parseInt(address, 16)).toOption
  }

  override def runOnPart(method: Method): Iterator[DiffGraph] = {
    println(s"Adding edges for method ${method.name}")
    implicit val diffGraph: DiffGraph.Builder = DiffGraph.newBuilder
    method.ast.filter(_.isInstanceOf[Call]).map(_.asInstanceOf[Call])
      .nameExact("<operator>.goto")
      .where(_.argument.order(1).isLiteral)
      .foreach { sourceCall =>
        println(s"Found source call $sourceCall")
        sourceCall.argument.order(1).code.l.headOption.flatMap(parseAddress) match {
          case Some(destinationAddress) =>
            method.ast.lineNumber(destinationAddress).foreach { destination =>
              println(s"Adding diff graph edge to $destinationAddress")
              diffGraph.addEdge(sourceCall, destination, EdgeTypes.CFG)
            }
          case _ => // Ignore for now
          /*
            TODO:
              - Ask ghidra to resolve addresses of JMPs
           */
        }
      }
    Iterator(diffGraph.build())
  }
}
