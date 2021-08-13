package io.joern.ghidra2cpg.querying.x86

import io.joern.ghidra2cpg.fixtures.GhidraBinToCpgSuite
import io.shiftleft.semanticcpg.language._

class CFGTests extends GhidraBinToCpgSuite {

  override def beforeAll(): Unit = {
    super.beforeAll()
    buildCpgForBin("x86_64.bin")
  }

  "should have the cfgFirst node with the value set in" in {
    val cfgFirst = cpg.method.name("main").cfgFirst.l.head
    cfgFirst.code shouldBe "PUSH RBP"
    cfgFirst.order shouldBe 0
  }
}
