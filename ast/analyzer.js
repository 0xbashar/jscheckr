#!/usr/bin/env node
/**
 * JSHunter AST Analyzer
 * Performs deep JavaScript analysis using Babel AST parser
 */

const fs = require('fs');
const parser = require('@babel/parser');
const traverse = require('@babel/traverse').default;
const t = require('@babel/types');

class ASTAnalyzer {
    constructor(code, filePath) {
        this.code = code;
        this.filePath = filePath;
        this.findings = {
            dom_xss: [],
            taint_flows: [],
            dangerous_functions: [],
            data_flows: []
        };
        
        try {
            this.ast = parser.parse(code, {
                sourceType: 'unambiguous',
                plugins: [
                    'jsx',
                    'typescript',
                    'decorators-legacy',
                    'classProperties',
                    'objectRestSpread',
                    'optionalChaining',
                    'nullishCoalescingOperator'
                ],
                errorRecovery: true
            });
        } catch (e) {
            console.error(`Parse error in ${filePath}: ${e.message}`);
            this.ast = null;
        }
    }
    
    analyze() {
        if (!this.ast) return this.findings;
        
        this._detectDOMXSS();
        this._traceDataFlow();
        this._detectDangerousPatterns();
        
        return this.findings;
    }
    
    _detectDOMXSS() {
        const sources = new Set([
            'location', 'location.href', 'location.search', 'location.hash',
            'document.URL', 'document.referrer', 'window.name',
            'localStorage.getItem', 'sessionStorage.getItem',
            'document.cookie', 'postMessage'
        ]);
        
        const sinks = new Set([
            'innerHTML', 'outerHTML', 'document.write', 'document.writeln',
            'eval', 'Function', 'setTimeout', 'setInterval',
            'insertAdjacentHTML', 'location.href'
        ]);
        
        let sourceVariables = new Map();
        let sinkUsages = [];
        
        traverse(this.ast, {
            // Detect source assignments
            AssignmentExpression(path) {
                const left = path.node.left;
                const right = path.node.right;
                
                if (t.isMemberExpression(right)) {
                    const sourceStr = this._getMemberExpressionString(right);
                    if (sourceStr && sources.has(sourceStr)) {
                        if (t.isIdentifier(left)) {
                            sourceVariables.set(left.name, {
                                source: sourceStr,
                                line: path.node.loc.start.line
                            });
                        }
                    }
                }
            },
            
            // Detect variable declarations with sources
            VariableDeclarator(path) {
                const init = path.node.init;
                if (init && t.isMemberExpression(init)) {
                    const sourceStr = this._getMemberExpressionString(init);
                    if (sourceStr && sources.has(sourceStr)) {
                        sourceVariables.set(path.node.id.name, {
                            source: sourceStr,
                            line: path.node.loc.start.line
                        });
                    }
                }
            },
            
            // Detect sink usage with tainted variables
            CallExpression(path) {
                const callee = path.node.callee;
                
                // Direct dangerous calls
                if (t.isIdentifier(callee) && ['eval', 'Function'].includes(callee.name)) {
                    if (path.node.arguments.length > 0) {
                        const arg = path.node.arguments[0];
                        if (t.isIdentifier(arg) && sourceVariables.has(arg.name)) {
                            this.findings.dom_xss.push({
                                type: 'DOM XSS',
                                source: sourceVariables.get(arg.name).source,
                                sink: callee.name,
                                file: this.filePath,
                                line: path.node.loc.start.line,
                                severity: 'CRITICAL'
                            });
                        }
                    }
                }
                
                // Method calls
                if (t.isMemberExpression(callee)) {
                    const method = callee.property.name;
                    const objStr = this._getExpressionString(callee.object);
                    
                    if (sinks.has(method) || (objStr && sinks.has(`${objStr}.${method}`))) {
                        sinkUsages.push({
                            method: method,
                            object: objStr,
                            args: path.node.arguments,
                            line: path.node.loc.start.line
                        });
                    }
                }
            },
            
            // Detect innerHTML assignments
            AssignmentExpression: {
                exit(path) {
                    const left = path.node.left;
                    const right = path.node.right;
                    
                    if (t.isMemberExpression(left) && 
                        (left.property.name === 'innerHTML' || 
                         left.property.name === 'outerHTML')) {
                        
                        if (t.isIdentifier(right) && sourceVariables.has(right.name)) {
                            this.findings.dom_xss.push({
                                type: 'DOM XSS',
                                source: sourceVariables.get(right.name).source,
                                sink: left.property.name,
                                file: this.filePath,
                                line: path.node.loc.start.line,
                                severity: 'HIGH'
                            });
                        }
                    }
                }
            }
        });
        
        // Add sink usages to findings
        sinkUsages.forEach(sink => {
            this.findings.dom_xss.push({
                type: 'Potential DOM XSS',
                sink: sink.method,
                object: sink.object,
                file: this.filePath,
                line: sink.line,
                severity: 'MEDIUM'
            });
        });
    }
    
    _traceDataFlow() {
        // Simple taint analysis
        const taintSources = ['location', 'document.cookie', 'localStorage', 'sessionStorage'];
        const taintSinks = ['eval', 'innerHTML', 'document.write', 'Function'];
        
        let taintedVars = new Set();
        
        traverse(this.ast, {
            VariableDeclarator(path) {
                const init = path.node.init;
                if (init && this._isTainted(init, taintSources)) {
                    taintedVars.add(path.node.id.name);
                }
            },
            
            AssignmentExpression(path) {
                if (t.isIdentifier(path.node.left) && 
                    this._isTainted(path.node.right, taintSources)) {
                    taintedVars.add(path.node.left.name);
                }
            },
            
            CallExpression(path) {
                if (t.isIdentifier(path.node.callee) && 
                    taintSinks.includes(path.node.callee.name)) {
                    
                    path.node.arguments.forEach(arg => {
                        if (t.isIdentifier(arg) && taintedVars.has(arg.name)) {
                            this.findings.taint_flows.push({
                                source: 'Tainted variable',
                                sink: path.node.callee.name,
                                file: this.filePath,
                                line: path.node.loc.start.line,
                                variable: arg.name
                            });
                        }
                    });
                }
            }
        });
    }
    
    _detectDangerousPatterns() {
        traverse(this.ast, {
            CallExpression(path) {
                // Detect eval with concatenation
                if (path.node.callee.name === 'eval' && 
                    path.node.arguments.length === 1 &&
                    t.isBinaryExpression(path.node.arguments[0], { operator: '+' })) {
                    
                    this.findings.dangerous_functions.push({
                        type: 'Dangerous eval with concatenation',
                        file: this.filePath,
                        line: path.node.loc.start.line,
                        severity: 'CRITICAL'
                    });
                }
                
                // Detect Function constructor with strings
                if (path.node.callee.name === 'Function' && 
                    path.node.arguments.some(arg => t.isStringLiteral(arg))) {
                    
                    this.findings.dangerous_functions.push({
                        type: 'Dynamic Function constructor',
                        file: this.filePath,
                        line: path.node.loc.start.line,
                        severity: 'HIGH'
                    });
                }
            }
        });
    }
    
    _isTainted(node, sources) {
        if (t.isMemberExpression(node)) {
            const str = this._getMemberExpressionString(node);
            return str && sources.some(source => str.includes(source));
        }
        return false;
    }
    
    _getMemberExpressionString(node) {
        if (t.isIdentifier(node)) {
            return node.name;
        }
        if (t.isMemberExpression(node)) {
            const obj = this._getMemberExpressionString(node.object);
            const prop = node.computed ? '[computed]' : node.property.name;
            return obj ? `${obj}.${prop}` : null;
        }
        if (t.isThisExpression(node)) {
            return 'this';
        }
        return null;
    }
    
    _getExpressionString(node) {
        if (t.isIdentifier(node)) return node.name;
        if (t.isMemberExpression(node)) return this._getMemberExpressionString(node);
        return null;
    }
}

// Main execution
if (require.main === module) {
    const filePath = process.argv[2];
    
    if (!filePath) {
        console.error('Usage: node analyzer.js <javascript-file>');
        process.exit(1);
    }
    
    try {
        const code = fs.readFileSync(filePath, 'utf-8');
        const analyzer = new ASTAnalyzer(code, filePath);
        const results = analyzer.analyze();
        
        console.log(JSON.stringify(results, null, 2));
    } catch (e) {
        console.error(`Error: ${e.message}`);
        process.exit(1);
    }
}

module.exports = ASTAnalyzer;
