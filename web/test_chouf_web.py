"""What a visitor types reaches the sandbox as one argument, and only when it is well formed."""
import unittest

import chouf_web as w


class Validation(unittest.TestCase):
    def test_well_formed_targets_pass(self):
        for kind, t in [("script", "https://sh.rustup.rs"), ("script", "https://get.docker.com/?channel=stable"),
                        ("script", "https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.3/install.sh"),
                        ("npm", "left-pad"), ("npm", "@types/node@22.1.0"), ("npm", "react@^18"),
                        ("pip", "requests"), ("pip", "requests==2.32.3"), ("pip", "uvicorn[standard]>=0.30")]:
            self.assertEqual(w.valid(kind, t), t, (kind, t))

    def test_anything_else_is_refused(self):
        for kind, t in [("script", "http://sh.rustup.rs"), ("script", "file:///etc/passwd"), ("script", "https://x.y/$(id)"),
                        ("script", "https://x.y/a b"), ("script", "https://x.y/`id`"), ("script", "-o /tmp/x https://x.y"),
                        ("npm", "git+https://evil/x.git"), ("npm", "user/repo"), ("npm", "./local"), ("npm", "--ignore-scripts=false"),
                        ("npm", "x;id"), ("pip", "git+https://evil/x"), ("pip", "./local"), ("pip", "-r requirements.txt"),
                        ("pip", "--index-url=https://evil x"), ("pip", "x; id"), ("shell", "id"), ("npm", ""), ("pip", "a" * 301)]:
            self.assertIsNone(w.valid(kind, t), (kind, t))

    def test_the_target_is_never_shell_code(self):
        for kind in ("script", "npm", "pip"):
            argv = w.chouf_argv(kind, "TARGET", "en")
            self.assertEqual(argv[-1], "TARGET")
            self.assertEqual(sum("TARGET" in a for a in argv), 1, argv)
            self.assertIn("--memory", argv)


class Arguments(unittest.TestCase):
    def test_plain_words_pass_and_shell_does_not(self):
        self.assertEqual(w.valid_args("-y --default-toolchain=stable"), ["-y", "--default-toolchain=stable"])
        self.assertEqual(w.valid_args(""), [])
        for bad in ["-y; id", "$(id)", "`id`", "a|b", "> /etc/x", "1 2 3 4 5 6 7", "'x'", "--x=\"y\""]:
            self.assertIsNone(w.valid_args(bad), bad)
        argv = w.chouf_argv("script", "https://sh.rustup.rs", "en", ["-y"])
        self.assertEqual(argv[-2:], ["https://sh.rustup.rs", "-y"])


if __name__ == "__main__":
    unittest.main()
