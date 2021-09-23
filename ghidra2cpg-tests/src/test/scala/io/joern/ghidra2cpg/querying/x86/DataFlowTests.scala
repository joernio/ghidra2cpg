package io.joern.ghidra2cpg.querying.x86

import io.joern.ghidra2cpg.fixtures.GhidraBinToCpgSuite
import io.shiftleft.codepropertygraph.generated.nodes
import io.shiftleft.dataflowengineoss.language._
import io.shiftleft.dataflowengineoss.queryengine.EngineContext
import io.shiftleft.dataflowengineoss.semanticsloader.{Parser, Semantics}
import io.shiftleft.semanticcpg.language.{ICallResolver, _}
import io.shiftleft.utils.ProjectRoot

class DataFlowTests extends GhidraBinToCpgSuite {

  override def beforeAll: Unit = {
    super.beforeAll()
    buildCpgForBin("x86_64.bin")
  }

  def flowToResultPairs(path: Path): List[String] = {
    val pairs = path.elements.map {
      case point: nodes.MethodParameterIn => {
        val method      = point.method.head
        val method_name = method.name
        val code        = s"$method_name(${method.parameter.l.sortBy(_.order).map(_.code).mkString(", ")})"
        code
      }
      case point => (point.statement.repr)
    }
    pairs.headOption
      .map(x => x :: pairs.sliding(2).collect { case Seq(a, b) if a != b => b }.toList)
      .getOrElse(List())
  }

  "The data flow should contain " in {
    implicit val resolver: ICallResolver = NoResolve
    val semanticsFilename = ProjectRoot.relativise(
      "ghidra2cpg-tests/src/resources/dataflowengineoss/src/test/resources/default.semantics"
    )
    val semantics: Semantics            = Semantics.fromList(new Parser().parseFile(semanticsFilename))
    implicit var context: EngineContext = EngineContext(semantics)

    def source = cpg.method.name("dataflow").call.argument.code("1")
    def sink = cpg.method
      .name("dataflow")
      .call
      .where(_.argument.order(2).code("ECX"))
      .argument
      .order(1)
      .code("EAX")
    val flows = sink.reachableByFlows(source).l

    flows.map(flowToResultPairs).toSet shouldBe
      Set(List("ADD EAX,0x1", "MOV EDX,EAX", "MOV ECX,EDX", "MOV EAX,ECX"))
  }
}
