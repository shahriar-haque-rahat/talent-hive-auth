import { Column, CreateDateColumn, Entity, PrimaryGeneratedColumn, UpdateDateColumn } from "typeorm";

@Entity({
    name: 'users'
})
export class User {
    @PrimaryGeneratedColumn({ type: 'mediumint', unsigned: true, comment: 'User ID' })
    id: number;

    @Column({ type: 'varchar', length: 40, nullable: false })
    uid: string;

    @Column({ type: 'varchar', length: 100, nullable: false })
    fullName: string;

    @Column({ type: 'varchar', length: 40, nullable: false })
    userName: string;

    @Column({ type: 'varchar', length: 100, nullable: false })
    email: string;

    @Column({ type: 'varchar', length: 255, nullable: false })
    password: string;

    @Column({ type: 'varchar', length: 40, nullable: true })
    status: string;

    @Column({ type: 'varchar', length: 40, nullable: true })
    role: string;

    @CreateDateColumn({ type: 'datetime', nullable: true })
    createdOn: Date;

    @UpdateDateColumn({ type: 'datetime', nullable: true })
    modifiedOn: Date;

}