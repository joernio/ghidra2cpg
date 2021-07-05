package x86.io.joern.ghidra2cpg.querying

import io.shiftleft.dataflowengineoss.layers.dataflows.{OssDataFlow, OssDataFlowOptions}
import io.shiftleft.semanticcpg.layers.LayerCreatorContext
import io.shiftleft.codepropertygraph.generated.nodes
import io.shiftleft.dataflowengineoss.language._
import io.shiftleft.dataflowengineoss.queryengine.EngineContext
import io.shiftleft.dataflowengineoss.semanticsloader.{Parser, Semantics}
import io.shiftleft.semanticcpg.language.{ICallResolver, _}

class DataFlowTests extends GhidraCodeToCpgSuite {
  override val code: String =
    """
      | #include <stdio.h>
      | int dataflow1() {
      |  asm ("add $1, %eax\n\t"
      |    "mov %eax, %edx\n\t"
      |    "mov %edx, %ecx\n\t"
      |    "mov %ecx, %eax");
      | }
      |
      | int main() {
      | }
      |""".stripMargin

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
    val semanticsFilename                = "src/resources/dataflowengineoss/src/test/resources/default.semantics"
    val semantics: Semantics             = Semantics.fromList(new Parser().parseFile(semanticsFilename))
    implicit var context: EngineContext  = EngineContext(semantics)

    def source = cpg.method.name("dataflow1").call.argument.code("1")
    def sink = cpg.method
      .name("dataflow1")
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
