# Moi truong bien dich LaTeX cho hai ban bao cao (LNCS va IEEE), dung XeLaTeX.
# Build:  docker build -t nhom14-latex tools/latex
FROM texlive/texlive:latest-medium
# Goi ma lop llncs can nhung ban medium khong co (tlmgr phai tu cap nhat truoc)
RUN tlmgr update --self && tlmgr install aliascnt
