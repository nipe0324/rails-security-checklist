class User < ApplicationRecord

  # http://guides.rubyonrails.org/security.html#regular-expressions
  # Bad: raise error
  # The provided regular expression is using multiline anchors (^ or $), which may present a security risk.
  # Did you mean to use \A and \z, or forgot to add the :multiline => true option?
  # validates :homepage, format: { with: /^https?:\/\/[^\n]+$/i }

  # Good
  validates :homepage, format: { with: /\Ahttps?:\/\/[^\n]+\z/i }
end
