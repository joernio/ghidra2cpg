package io.joern.ghidra2cpg.querying.x86

import io.joern.ghidra2cpg.fixtures.GhidraBinToCpgSuite
import io.shiftleft.semanticcpg.language._

class LocalNodeTests extends GhidraBinToCpgSuite {

  override def beforeAll(): Unit = {
    super.beforeAll()
    buildCpgForBin("x86_64.bin")
  }

  "should contain exactly one node with all mandatory fields set" in {
    cpg.method.name("localNodeTests").local.l.head match {
      case x =>
        x.name shouldBe "local_c"
        x.code shouldBe "[undefined4 local_c@Stack[-0xc]:4]"
        x.typeFullName shouldBe "undefined4"
      case _ => fail()
    }
  }
}
