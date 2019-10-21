require 'benchmark'
require 'active_support'
require 'active_support/core_ext'
require_relative 'crawl'

class Crawler
  def crawl
    while true
      @@recalculate = false
      puts Benchmark.measure { @@recalculate = crawl_now }
      if @@recalculate == true
        puts Benchmark.measure { calculate_rank_numbers }
        puts Benchmark.measure { calculate_state_ranks }
      end
      recalculate = false
      sleep 45
    end
  end
end

Crawler.new.crawl