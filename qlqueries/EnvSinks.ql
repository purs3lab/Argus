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
    // we need to get process.env
    result = DataFlow::globalVarRef("process").getAPropertyRead("env").getAPropertyReference()
}

class MyConfiguration extends TaintTracking::Configuration {
    MyConfiguration() {
        this = "EnvSinks"
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

from MyConfiguration  cfg, DataFlow::PathNode source, DataFlow::PathNode sink, IndexExpr e, DotExpr d, string test, string name
where cfg.hasFlowPath(source, sink) and
    test = sink.getNode().asExpr().getParent().(CallExpr).getCalleeName() and
    ((e = source.getNode().asExpr() and name = e.getPropertyName()) or
    (d = source.getNode().asExpr() and name = d.getPropertyName()))
select name, source, sink, test