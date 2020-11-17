
"""
Distance module

Find distance between sequences

Written by Marshall Beddoe <mbeddoe@baselineresearch.net>
Copyright (c) 2004 Baseline Research

Licensed under the LGPL
"""

#
# Note: Gaps are denoted by the integer value 256 as to avoid '_' problems
#

# import align, zlib
from numpy import *
import Needleman

class Distance:

    """Implementation of classify base class"""

    def __init__(self, sequences):
        self.sequences = sequences
        self.N = len(sequences)

        # NxN Distance matrix
        self.dmx = zeros((self.N, self.N), float64)

        for i in range(len(sequences)):
            for j in range(len(sequences)):
                self.dmx[i][j] = -1

        self._go()

    def __repr__(self):
        return "%s" % self.dmx

    def __getitem__(self, i):
        return self.dmx[i]

    def __len__(self):
        return len(self.dmx)

    def _go(self):
        """Perform distance calculations"""
        pass

class LocalAlignment(Distance):

    """Distance through local alignment similarity"""

    def __init__(self, sequences, smx=None):
        self.smx = smx

        # If similarity matrix is None, make a quick identity matrix
        if self.smx == None:

            self.smx = zeros((257, 257), float64)

            for i in range(257):
                for j in range(257):
                    if i == j:
                        self.smx[i][j] = 1.0
                    else:
                        self.smx[i][j] = 0.0

        Distance.__init__(self, sequences)

    def _go(self):

        # Similarity matrix
        similar = zeros((self.N, self.N), float64)

        for i in range(self.N):
            for j in range(self.N):
                similar[i][j] = -1

        #
        # Compute similarity matrix of SW scores
        #
        for i in range(self.N):
            for j in range(self.N):

                if similar[i][j] >= 0:
                    continue

                # (nseq1, nseq2, edits1, edits2, score, gaps) = \
                #     align.SmithWaterman(seq1, seq2, self.smx, 0, 0)
                score=Needleman.SmithWunsh(self.sequences[i],self.sequences[j])
                similar[i][j] = similar[j][i] = score

        #
        # Compute distance matrix of SW scores
        #
        for i in range(self.N):
            for j in range(self.N):

                if self.dmx[i][j] >= 0:
                    continue

                self.dmx[i][j] = 1 - (similar[i][j] / similar[i][i])
                self.dmx[j][i] = self.dmx[i][j]
