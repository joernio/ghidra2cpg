package x86.io.joern.ghidra2cpg.querying

import io.joern.ghidra2cpg.Ghidra2Cpg
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.cpgloading.{CpgLoader, CpgLoaderConfig}
import io.shiftleft.semanticcpg.testfixtures.{CodeToCpgFixture, LanguageFrontend}
import org.apache.commons.io.FileUtils

import java.nio.file.{Files, Paths}

class GhidraFrontend extends LanguageFrontend {
  override val fileSuffix: String = ""

  override def execute(sourceCodeFile: java.io.File): Cpg = {
    val dir = Files.createTempDirectory("ghidra2cpg-tests").toFile
    Runtime.getRuntime.addShutdownHook(new Thread(() => FileUtils.deleteQuietly(dir)))

    val tempDir = Files.createTempDirectory("ghidra2cpg").toFile
    Runtime.getRuntime.addShutdownHook(new Thread(() => FileUtils.deleteQuietly(tempDir)))

    val cpgBin    = dir.getAbsolutePath
    val inputFile = s"${Paths.get(".").toAbsolutePath}/src/test/testbinaries/x86_64.bin"
    new Ghidra2Cpg(
      inputFile,
      Some(cpgBin)
    ).createCpg()

    val odbConfig = overflowdb.Config.withDefaults().withStorageLocation(cpgBin)
    val config    = CpgLoaderConfig.withDefaults.withOverflowConfig(odbConfig)
    CpgLoader.loadFromOverflowDb(config)
  }

}

class GhidraCodeToCpgSuite extends CodeToCpgFixture(new GhidraFrontend) {}
