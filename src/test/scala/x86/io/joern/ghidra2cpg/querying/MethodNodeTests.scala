package x86.io.joern.ghidra2cpg.querying

import io.shiftleft.semanticcpg.language._

class MethodNodeTests extends GhidraCodeToCpgSuite {

  override val code: String = ""

  "should contain exactly one node with all mandatory fields set" in {
    cpg.method.name("main").l match {
      case List(x) =>
        x.name shouldBe "main"
      case _ => fail()
    }
  }
}
