package x86.io.joern.ghidra2cpg.querying

import io.shiftleft.semanticcpg.language._

class RefNodeTests extends GhidraCodeToCpgSuite {

  override val code: String =
    """
      | int main() {
      |   int x = 10;
      |   int y = 10;
      |}
      |""".stripMargin

  "should contain exactly one local with one referencing identifier " in {
    cpg.method.name("main").local.referencingIdentifiers.l match {
      case List(x, y) =>
        x.code shouldBe "local_c"
        y.code shouldBe "local_10"
      case _ => fail()
    }
  }
}
