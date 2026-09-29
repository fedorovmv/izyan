// Module boundary marker: keeps product sources out of the parent
// module's ./... builds. Product sources are compiled only inside the
// generated eval/.gen/<case>/ repositories, whose manifests are
// materialized from corpus dep pins. Dependency pins live in
// eval/corpus-real.json — never in this file.
module eval-products

go 1.21
