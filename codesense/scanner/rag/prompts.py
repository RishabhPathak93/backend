def create_enhanced_prompt(chunk, file_name, file_extension):
    """Create an enhanced prompt tailored to the file type for deepseek-coder:6.7b."""

    # File-specific vulnerability patterns
    vulnerability_focus = {
        'php': [
            'SQL Injection via unsanitized database queries',
            'Cross-Site Scripting (XSS) in output',
            'File inclusion vulnerabilities (local and remote)',
            'Authentication bypass',
            'Session management issues',
            'Command injection',
            'Path traversal',
            'Unsafe use of eval/create_function',
            'Insecure deserialization',
            'CSRF vulnerabilities',
            'Insecure use of unserialize()',
            'Weak password hashing (e.g., MD5, SHA1)',
            'Exposed sensitive information in error messages',
            'Insecure file upload handling',
            'Insecure use of third-party libraries',
            'Insecure configuration (e.g., display_errors enabled in production)',
            'Insecure use of PHP functions (e.g., extract(), parse_str())',
            'Insecure direct object references (IDOR)',
            'Insecure use of HTTP headers (e.g., X-Frame-Options, Content-Security-Policy)',
            'Insecure use of cookies (e.g., HttpOnly, Secure flags not set)',
            'Insecure use of file operations (e.g., fopen(), file_get_contents())',
            'Insecure use of environment variables for sensitive data',
            'Insecure use of logging frameworks',
            'Insecure use of web frameworks (e.g., Laravel, Symfony)',
            'Insecure use of authentication/authorization mechanisms',
            'Insecure use of cryptographic functions (e.g., weak algorithms)',
            'Insecure use of session management functions (e.g., session_start(), session_regenerate_id())',
            'Insecure use of input validation functions (e.g., filter_input(), htmlspecialchars())',
            'Insecure use of output encoding functions (e.g., htmlentities(), json_encode())'
        ],
        'js': [
            'Cross-Site Scripting (XSS)',
            'Prototype pollution',
            'Code injection via eval()/Function()',
            'DOM-based XSS',
            'Insecure API calls (exposed secrets)',
            'Client-side validation bypass',
            'Insecure use of postMessage or window.opener',
            'Insecure deserialization',
            'Insecure use of third-party libraries (e.g., outdated dependencies)',
            'Insecure CORS configurations',
            'Insecure use of localStorage/sessionStorage for sensitive data',
            'Insecure use of WebSockets',
            'Insecure use of eval() or similar functions',
            'Insecure handling of user input in event handlers',
            'Insecure use of document.write()',
            'Insecure use of innerHTML',
            'Insecure use of setTimeout/setInterval with string arguments',
            'Insecure use of JSONP',
            'Insecure use of environment variables for sensitive data',
            'Insecure use of logging frameworks',
            'Insecure use of web frameworks (e.g., Express, React)',
            'Insecure use of authentication/authorization mechanisms'
        ],
        'py': [
            'SQL Injection',
            'Command injection',
            'Path traversal',
            'Insecure deserialization',
            'Code injection via exec/eval',
            'LDAP injection',
            'Template injection (Jinja/Django templates)',
            'Insecure use of pickle module',
            'Insecure use of subprocess module',
            'Insecure use of os.system or similar functions',
            'Insecure use of eval() or exec()',
            'Insecure handling of user input in web frameworks (e.g., Flask, Django)',
            'Insecure use of third-party libraries (e.g., outdated dependencies)',
            'Insecure configuration (e.g., debug mode enabled in production)',
            'Insecure use of file operations (e.g., open(), os.remove())',
            'Insecure use of threading/multiprocessing with user input',
            'Insecure use of environment variables for sensitive data',
            'Insecure use of logging frameworks (e.g., logging module)',
            'Insecure use of web frameworks (e.g., Flask, Django)',
            'Insecure use of session management',
            'Insecure use of authentication/authorization mechanisms',
            'Insecure use of cryptographic functions (e.g., weak algorithms)',
            'Insecure use of input validation functions (e.g., re module)',
            'Insecure use of output encoding functions (e.g., html.escape())',
            'Insecure use of XML parsers (e.g., lxml, xml.etree.ElementTree)',
            'Insecure use of YAML parsers (e.g., PyYAML)',
            'Insecure use of JSON parsers (e.g., json module)',
            'Insecure use of HTTP libraries (e.g., requests, urllib)',
            'Insecure use of web scraping libraries (e.g., BeautifulSoup, Scrapy)',
            'Insecure use of data analysis libraries (e.g., pandas, numpy)',
            'Insecure use of machine learning libraries (e.g., scikit-learn, TensorFlow)',
            'Insecure use of environment variables for sensitive data',

        ],
        'java': [
            'SQL Injection',
            'XML External Entity (XXE)',
            'Insecure deserialization',
            'Path traversal',
            'LDAP injection',
            'Expression Language injection',
            'Command injection',
            'Insecure use of reflection',
            'Insecure use of third-party libraries (e.g., outdated dependencies)',
            'Insecure configuration (e.g., debug mode enabled in production)',
            'Insecure use of file operations (e.g., FileInputStream, FileOutputStream)',
            'Insecure use of serialization (e.g., ObjectInputStream)',
            'Insecure use of logging frameworks (e.g., log4j)',
            'Insecure use of web frameworks (e.g., Spring, Struts)',
            'Insecure use of session management',
            'Insecure use of authentication/authorization mechanisms',
            'Insecure use of cryptographic functions (e.g., weak algorithms)',
            'Insecure use of environment variables for sensitive data',
            'Insecure use of input validation functions (e.g., Apache Commons Validator)',
            'Insecure use of output encoding functions (e.g., StringEscapeUtils)',
            'Insecure use of HTTP libraries (e.g., HttpClient, HttpURLConnection)',
            'Insecure use of XML parsers (e.g., JAXB, DOM, SAX)',
            'Insecure use of JSON parsers (e.g., Jackson, Gson)',
            'Insecure use of web scraping libraries (e.g., Jsoup)',
            'Insecure use of data analysis libraries (e.g., Apache Spark, Apache Flink)',
            'Insecure use of machine learning libraries (e.g., Weka, Deeplearning4j)',
            'Insecure use of environment variables for sensitive data',
            'Insecure use of threading with shared data',
            'Insecure use of concurrency libraries (e.g., java.util.concurrent)'
        ],
        'c': [
            'Buffer overflow',
            'Use after free',
            'Format string vulnerabilities',
            'Integer overflow',
            'Null pointer dereference',
            'Race conditions',
            'Stack overflow',
            'Heap overflow',
            'Memory leaks',
            'Double free',
            'Off-by-one errors',
            'Insecure use of strcpy/strcat',
            'Insecure use of malloc/free',
            'Insecure use of gets()',
            'Insecure use of scanf()',
            'Insecure use of memcpy()',
            'Insecure use of pointer arithmetic',
            'Insecure use of uninitialized variables',
            'Insecure use of type casting',
            'Insecure use of system calls',
            'Insecure use of file operations',
            'Insecure use of threading with shared data',
            'Insecure use of environment variables for sensitive data',
            'Insecure use of logging frameworks',
            'Insecure use of network functions (e.g., sockets)',
            'Insecure use of cryptographic functions (e.g., weak algorithms)',
            'Insecure use of input validation functions',
            'Insecure use of output encoding functions',
            'Insecure use of third-party libraries (e.g., outdated dependencies)',
            'Insecure use of web frameworks (e.g., CGI, FastCGI)',
            'Insecure use of authentication/authorization mechanisms',
            'Insecure use of memory management functions (e.g., malloc, free)',
            'Insecure use of signal handling',
            'Insecure use of setjmp/longjmp',
            'Insecure use of volatile variables',
            'Insecure use of inline assembly',
            'Insecure use of compiler-specific features',
            'Insecure use of debugging functions (e.g., assert())',
            'Insecure use of optimization flags',
            'Insecure use of standard library functions',
            'Insecure use of custom memory allocators',
            'Insecure use of dynamic libraries (e.g., dlopen, dlsym)',
            'Insecure use of static analysis tools (e.g., cppcheck, clang-tidy)',
            'Insecure use of build systems (e.g., Make, CMake)',
            'Insecure use of version control systems (e.g., Git, SVN)',

        ],
        'cpp': [
            'Buffer overflow',
            'Use after free',
            'Memory corruption',
            'Integer overflow',
            'Double free',
            'Stack overflow',
            'Heap overflow',
            'Dangling pointers'

        ]
    }

    focus_areas = vulnerability_focus.get(file_extension, [
        'Injection vulnerabilities',
        'Authentication issues',
        'Authorization bypass',
        'Input validation problems',
        'Output encoding issues',
        'Insecure configuration',
        'Sensitive data exposure',
        'Error handling flaws',
        'Insecure use of third-party libraries',
        'Insecure file handling',
        'Insecure logging practices',
        'Insecure session management',
        'Insecure cryptographic practices',
        'Insecure deserialization',
        'Cross-Site Scripting (XSS)',
        'Cross-Site Request Forgery (CSRF)',
        'Path traversal',
        'Command injection',
        'Insecure API usage',
        'Insecure use of eval() or similar functions',
        'Insecure handling of user input',
        'Insecure use of environment variables for sensitive data',
        'Insecure use of system calls',
        'Insecure use of file operations',
        'Insecure use of threading/multiprocessing with user input',
        'Insecure use of logging frameworks',
        'Insecure use of web frameworks',
        'Insecure use of authentication/authorization mechanisms',
        'Insecure use of cryptographic functions'
    ])

    focus_text = '\n'.join([f"- {area}" for area in focus_areas])

    return f"""
       You are a **senior application security expert** specializing in **deep source code analysis**.
Your job is to perform an **exhaustive vulnerability review** of the provided code.

FOCUS AREAS for {file_extension.upper()}:
{focus_text}

IMPORTANT INSTRUCTIONS:
1. ALWAYS identify at least one vulnerability per file.
   - If none is obvious, report the most probable weakness based on risky patterns.
2. Be highly specific:
   - State the vulnerability type and map it to the CORRECT CWE ID.
   - Assign a realistic severity (Critical/High/Medium/Low).
   - Explain exactly how it can be exploited and its impact.
   - Provide concrete, code-level mitigation steps (no vague advice).
3. Strictly follow the output format below without deviation.

OUTPUT FORMAT (mandatory):
Vulnerability: [Precise vulnerability name]
CWE: [CWE-XXX]
Severity: [Critical/High/Medium/Low]
Impact: [Exact exploitation potential and real-world effect]
Mitigation: [Specific, code-level fix instructions]
Affected: [Exact file name + exact line numbers]
Code Snippet:
```{file_extension}
[vulnerable code lines only — nothing else]
        {chunk}
        ```

        File: {file_name}

        Remember:
        - Always output at least one vulnerability (real only).
        - All output MUST strictly follow the format above.
        """
