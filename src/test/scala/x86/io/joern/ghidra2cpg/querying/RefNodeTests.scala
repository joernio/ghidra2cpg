package x86.io.joern.ghidra2cpg.querying

import io.shiftleft.semanticcpg.language._

class RefNodeTests extends GhidraCodeToCpgSuite {

  override val code: String = ""

  "should contain exactly one local with one referencing identifier " in {
    cpg.method.name("refNodeTests").local.referencingIdentifiers.l match {
      case List(x, y) =>
        x.code shouldBe "local_c"
        y.code shouldBe "local_10"
      case _ => fail()
    }
  }
}
