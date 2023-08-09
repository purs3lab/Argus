/**
 * @name DangerousSinks
 * @description Finding sinks
 * @kind path-problem
 * @tags security
 * @id javascipt/dangerous
 * @precision medium
 */

import javascript
import DataFlow::PathGraph

DataFlow::Node mainDangerCalls() {
    result = DataFlow::globalVarRef("eval").getACall().getArgument(0) or
    result = DataFlow::globalVarRef("setTimeout").getACall().getArgument(0) or
    result = DataFlow::globalVarRef("setInterval").getACall().getArgument(0) or
    result = DataFlow::globalVarRef("Function").getACall().getAnArgument() or
    result = DataFlow::globalVarRef("unserialize").getACall().getArgument(0)
}

DataFlow::Node ioActionCalls() {
    result = DataFlow::moduleImport("@actions/io").getAMemberCall("rmRF").getArgument(0) 
}

DataFlow::Node execActionCalls() {
    result = DataFlow::moduleImport("@actions/exec").getAMemberCall("exec").getArgument(0)
}

DataFlow::Node addPathCalls() {
    result = DataFlow::moduleImport("@actions/core").getAMemberCall("addPath").getAnArgument()
}

DataFlow::Node downloadToolCalls() {
    result = DataFlow::moduleImport("@actions/tool-cache").getAMemberCall("downloadTool").getArgument(0)
}

DataFlow::Node extract7zCalls() {
    result = DataFlow::moduleImport("@actions/tool-cache").getAMemberCall("extract7z").getArgument(0)
}

DataFlow::Node uploadArtifactsCalls() {
    result = DataFlow::moduleImport("@actions/artifact").getAMemberCall("uploadArtifact").getArgument(0) or
    result = DataFlow::moduleImport("@actions/artifact").getAMemberCall("uploadArtifact").getArgument(1) or
    result = DataFlow::moduleImport("@actions/artifact").getAMemberCall("uploadArtifact").getArgument(2)
}

DataFlow::Node fsCalls() {
    result = DataFlow::moduleImport("fs").getAMemberCall("write").getArgument(0) or
    result = DataFlow::moduleImport("fs").getAMemberCall("write").getArgument(1) or
    result = DataFlow::moduleImport("fs").getAMemberCall("writeFile").getArgument(0) or
    result = DataFlow::moduleImport("fs").getAMemberCall("writeFile").getArgument(1) or
    result = DataFlow::moduleImport("fs").getAMemberCall("writev").getArgument(0) or
    result = DataFlow::moduleImport("fs").getAMemberCall("writev").getArgument(1) or
    result = DataFlow::moduleImport("fs").getAMemberCall("read").getArgument(0) or
    result = DataFlow::moduleImport("fs").getAMemberCall("read").getArgument(1) or
    result = DataFlow::moduleImport("fs").getAMemberCall("readFile").getArgument(0) or
    result = DataFlow::moduleImport("fs").getAMemberCall("readFile").getArgument(1) or
    result = DataFlow::moduleImport("fs").getAMemberCall("append").getArgument(0) or
    result = DataFlow::moduleImport("fs").getAMemberCall("append").getArgument(1) or
    result = DataFlow::moduleImport("fs").getAMemberCall("appendFile").getArgument(0) or
    result = DataFlow::moduleImport("fs").getAMemberCall("appendFile").getArgument(1)
}

DataFlow::Node childPrcocessCalls() {
    result = DataFlow::moduleImport("child_process").getAMemberCall("exec").getAnArgument() or
    result = DataFlow::moduleImport("child_process").getAMemberCall("execSync").getAnArgument() or
    result = DataFlow::moduleImport("child_process").getAMemberCall("execFile").getAnArgument() or
    result = DataFlow::moduleImport("child_process").getAMemberCall("execFileSync").getAnArgument() or
    result = DataFlow::moduleImport("child_process").getAMemberCall("spawn").getAnArgument() or
    result = DataFlow::moduleImport("child_process").getAMemberCall("spawnSync").getAnArgument()
}

DataFlow::Node coreSources() { 
    // we need to get process.env
    result = DataFlow::globalVarRef("process").getAPropertyRead("env").getAPropertyReference()
}

class MyConfiguration extends TaintTracking::Configuration {
    MyConfiguration() {
        this = "LessEnvSinks"
    }

    override predicate isSource(DataFlow::Node source) {
        source = coreSources() 
    }

    override predicate isSink(DataFlow::Node sink) {
	    sink = mainDangerCalls() or
        sink = ioActionCalls() or
        sink = execActionCalls() or
        sink = childPrcocessCalls() or
        sink = fsCalls() or 
        sink = addPathCalls() or
        sink = downloadToolCalls() or
        sink = extract7zCalls() or
        sink = uploadArtifactsCalls()

    }
}

from MyConfiguration  cfg, DataFlow::PathNode source, DataFlow::PathNode sink, IndexExpr e, DotExpr d, string test, string name
where cfg.hasFlowPath(source, sink) and
    test = sink.getNode().asExpr().getParent().(CallExpr).getCalleeName() and
    ((e = source.getNode().asExpr() and name = e.getPropertyName()) or
    (d = source.getNode().asExpr() and name = d.getPropertyName()))
select name, source, sink, test