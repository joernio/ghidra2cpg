package io.joern.ghidra2cpg.fixtures

import io.joern.ghidra2cpg.Ghidra2Cpg
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.cpgloading.{CpgLoader, CpgLoaderConfig}
import io.shiftleft.semanticcpg.testfixtures.{BinToCpgFixture, LanguageFrontend}
import io.shiftleft.utils.ProjectRoot
import org.apache.commons.io.FileUtils

import java.nio.file.Files

class GhidraFrontend extends LanguageFrontend {
  override val fileSuffix: String = ""

  override def execute(inputFile: java.io.File): Cpg = {
    val dir = Files.createTempDirectory("ghidra2cpg-tests").toFile
    Runtime.getRuntime.addShutdownHook(new Thread(() => FileUtils.deleteQuietly(dir)))

    val tempDir = Files.createTempDirectory("ghidra2cpg").toFile
    Runtime.getRuntime.addShutdownHook(new Thread(() => FileUtils.deleteQuietly(tempDir)))

    val cpgBin = dir.getAbsolutePath
    new Ghidra2Cpg(
      inputFile,
      Some(cpgBin)
    ).createCpg()

    val odbConfig = overflowdb.Config.withDefaults().withStorageLocation(cpgBin)
    val config    = CpgLoaderConfig.withDefaults.withOverflowConfig(odbConfig)
    CpgLoader.loadFromOverflowDb(config)
  }

}

class GhidraBinToCpgSuite extends BinToCpgFixture(new GhidraFrontend) {
  override val binDirectory = ProjectRoot.relativise("ghidra2cpg-tests/src/test/testbinaries/")
}
