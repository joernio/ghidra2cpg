package io.joern.ghidra2cpg.passes

import ghidra.program.model.listing.Program
import ghidra.program.util.DefinedDataIterator
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.nodes
import io.shiftleft.passes.{DiffGraph, IntervalKeyPool, ParallelCpgPass}

import scala.jdk.CollectionConverters._
import scala.language.implicitConversions
import scala.util.Try

class LiteralPass(cpg: Cpg, currentProgram: Program, keyPool: IntervalKeyPool)
    extends ParallelCpgPass[String](
      cpg,
      keyPools = Some(keyPool.split(1))
    ) {

  override def partIterator: Iterator[String] = List("").iterator

  private def parseAddress(address: String): Option[Int] = {
    Try(Integer.parseInt(address, 16)).toOption
  }

  override def runOnPart(part: String): Iterator[DiffGraph] = {
    implicit val diffGraph: DiffGraph.Builder = DiffGraph.newBuilder
    DefinedDataIterator
      .definedStrings(currentProgram)
      .iterator
      .asScala
      .foreach { literal =>
        val node = nodes
          .NewLiteral()
          .code(literal.getValue.toString)
          .order(-1)
          .argumentIndex(-1)
          .typeFullName(literal.getValue.toString)
        diffGraph.addNode(node)
      //diffGraph.addEdge(blockNode, node, EdgeTypes.AST)
      }
    Iterator(diffGraph.build())
  }
}
