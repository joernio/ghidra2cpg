package x86.io.joern.ghidra2cpg.querying

import io.shiftleft.semanticcpg.language._

class CFGTests extends GhidraCodeToCpgSuite {

  override val code: String = ""

  "should have the cfgFirst node with the value set in" in {
    val cfgFirst = cpg.method.name("main").cfgFirst.l.head
    cfgFirst.code shouldBe "PUSH RBP"
    cfgFirst.order shouldBe 0
  }
}
