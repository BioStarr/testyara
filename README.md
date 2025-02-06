rule TestRule
{
    strings:
        $test_string = "This is a test string"
    condition:
        $test_string
}

