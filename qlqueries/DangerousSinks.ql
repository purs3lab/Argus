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
    result = DataFlow::globalVarRef("unserialize").getACall().getArgument(0)
}

DataFlow::Node execActionCalls() {
    result = DataFlow::moduleImport("@actions/exec").getAMemberCall("exec").getArgument(0)
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
    result = DataFlow::moduleImport("@actions/core").getAMemberCall("getInput") or
    result = DataFlow::moduleImport("@actions/core").getAMemberCall("getMultilineInput")
}


class MyConfiguration extends TaintTracking::Configuration {
    MyConfiguration() {
        this = "DangerousSinks"
    }

    override predicate isSource(DataFlow::Node source) {
        source = coreSources()
    }

    override predicate isSink(DataFlow::Node sink) {
	    sink = mainDangerCalls() or
        sink = execActionCalls() or
        sink = childPrcocessCalls()
    }
}

from MyConfiguration cfg, DataFlow::PathNode source, DataFlow::PathNode sink, CallExpr e, Expr arg, string test
where cfg.hasFlowPath(source, sink) and
    e = source.getNode().asExpr() and
    arg = e.getArgument(0) and 
    test = sink.getNode().asExpr().getParent().(CallExpr).getCalleeName()
select arg, source, sink, test

//from MyConfiguration cfg, DataFlow::PathNode source, DataFlow::PathNode sink
//where cfg.hasFlowPath(source, sink) 
//select source, sink, "issuehere"