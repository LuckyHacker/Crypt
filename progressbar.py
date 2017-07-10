import time
import sys

class ProgressBar:

	def __init__(self, job):
		self.progress = 0
		self.job = job
		self.start_time = time.time()

	def _progress(self):
		total_time = int(time.time() - self.start_time)
		self.eta = "0"
		self.elapsed = "0"
		self.p = float(self.progress) / float(self.job) * 100
		self.bar = "[" + "="*int(self.p/float(10)*2) + " "*(20-int(self.p/float(10)*2)) + "]"
		if self.job == self.progress+1:
			self.bar = "[" + "="*20 + "]"
			self.p = 100.0
		if self.p > 0:
			seconds_eta =  total_time * (100 / self.p) - total_time
			self.eta = str(int(seconds_eta)) + "s"
			if seconds_eta > 60:
				minutes_eta = seconds_eta / 60
				self.eta = str(int(minutes_eta)) + "m " + str(int(seconds_eta % 60)) + "s"
				if minutes_eta > 60:
					hours_eta = minutes_eta / 60
					self.eta = str(int(hours_eta)) + "h " + str(int(minutes_eta % 60)) + "m " + str(int(seconds_eta % 60)) + "s"
		if self.p > 0:
			self.elapsed = str(total_time) + "s"
			if total_time > 60:
				minutes_elapsed = total_time / 60
				self.elapsed = str(int(minutes_elapsed)) + "m " + str(total_time % 60) + "s"
				if minutes_elapsed > 60:
					hours_elapsed = minutes_elapsed / 60
					self.elapsed = str(int(hours_elapsed)) + "h " + str(int(minutes_elapsed % 60)) + "m " + str(int(total_time % 60)) + "s"

	def display(self):
		self._progress()
		sys.stdout.write("\r" + self.bar + " " + str(int(self.p)) + "% [ETA: " + self.eta + " | Elapsed: " + self.elapsed + "]     ")
		if self.progress == self.job-1:
			sys.stdout.write("\n")
		sys.stdout.flush()
		self.progress += 1
