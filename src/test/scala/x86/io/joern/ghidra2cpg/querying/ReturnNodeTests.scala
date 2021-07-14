package x86.io.joern.ghidra2cpg.querying

import io.shiftleft.semanticcpg.language._

class ReturnNodeTests extends GhidraCodeToCpgSuite {

  override val code: String = ""

  "should contain exactly one node with all mandatory fields set" in {
    cpg.method.name("main").methodReturn.l match {
      case List(x) =>
        x.order shouldBe 1
      case _ => fail()
    }
  }
}
